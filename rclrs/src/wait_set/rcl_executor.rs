use super::*;
use crate::{
    ActivityListenerCallback, Executor, ExecutorChannel, ExecutorRuntime, ExecutorWorkerOptions,
    PayloadTask, SpinConditions, WeakActivityListener, WorkerChannel,
};
use futures::{
    channel::oneshot,
    future::BoxFuture,
    task::{waker_ref, ArcWake},
    FutureExt,
};
use std::{
    any::Any,
    collections::BTreeMap,
    ffi::c_void,
    ptr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{channel, Receiver, Sender},
        Mutex,
    },
    task::Context as TaskContext,
    time::Instant,
};

// rcl_executor/executor.h enums.
const SUBSCRIPTION: i32 = 0;
const SERVICE: i32 = 2;
const CLIENT: i32 = 3;
const EVENT: i32 = 4;
const GUARD_CONDITION: i32 = 5;
const TIMER_OBSERVER: i32 = 7;
const READY: i32 = 0;
const ERROR: i32 = 4;

#[repr(C)]
struct Item {
    registration: u64,
    token: u64,
    kind: i32,
    entity: *const c_void,
    context: *mut c_void,
    count: usize,
    timer_info: rcl_timer_call_info_t,
    function: Option<unsafe extern "C" fn(*mut c_void)>,
}

impl Default for Item {
    fn default() -> Self {
        Self {
            registration: 0,
            token: 0,
            kind: 0,
            entity: ptr::null(),
            context: ptr::null_mut(),
            count: 0,
            timer_info: rcl_timer_call_info_t {
                expected_call_time: 0,
                actual_call_time: 0,
            },
            function: None,
        }
    }
}

extern "C" {
    fn rcl_executor_create(core: *mut *mut c_void) -> i32;
    fn rcl_executor_destroy(core: *mut c_void);
    fn rcl_executor_get_handle(core: *mut c_void) -> *mut c_void;
    fn rcl_executor_handle_destroy(handle: *mut c_void);
    fn rcl_executor_wake(handle: *mut c_void);
    fn rcl_executor_add(
        core: *mut c_void,
        kind: i32,
        entity: *const c_void,
        context: *mut c_void,
        group: u64,
        id: *mut u64,
    ) -> i32;
    fn rcl_executor_remove(core: *mut c_void, id: u64) -> i32;
    fn rcl_executor_wait(core: *mut c_void, ns: i64) -> i32;
    fn rcl_executor_next_excluding(
        core: *mut c_void,
        item: *mut Item,
        excluded: *const u64,
        count: usize,
    ) -> i32;
    fn rcl_executor_complete(core: *mut c_void, token: u64) -> i32;
}

struct Wake(*mut c_void);
// SAFETY: The retained C handle permits concurrent wakes and outlives its executor.
unsafe impl Send for Wake {}
unsafe impl Sync for Wake {}
impl ArcWake for Wake {
    fn wake_by_ref(this: &Arc<Self>) {
        unsafe { rcl_executor_wake(this.0) };
    }
}
impl Drop for Wake {
    fn drop(&mut self) {
        unsafe { rcl_executor_handle_destroy(self.0) };
    }
}

struct Core(*mut c_void);
// SAFETY: Only the owning runtime drives the core; channels use a separate retained handle.
unsafe impl Send for Core {}
impl Drop for Core {
    fn drop(&mut self) {
        unsafe { rcl_executor_destroy(self.0) };
    }
}
struct Claim {
    core: *mut c_void,
    token: u64,
}
impl Drop for Claim {
    fn drop(&mut self) {
        unsafe { rcl_executor_complete(self.core, self.token) }
            .ok()
            .unwrap();
    }
}

struct Entry {
    waitable: Waitable,
    registrations: Vec<(u64, *mut *const c_void)>,
    view: Option<WaitSet>,
    worker: usize,
}
// SAFETY: Slot pointers refer into the owned view and are accessed only by the runtime.
unsafe impl Send for Entry {}

impl Entry {
    fn new(
        core: &Core,
        mut waitable: Waitable,
        worker: usize,
        context: &Context,
    ) -> Result<Self, RclrsError> {
        let mut registrations = Vec::new();
        let mut add = |kind, entity, slot| {
            let mut id = 0;
            unsafe { rcl_executor_add(core.0, kind, entity, ptr::null_mut(), 0, &mut id) }.ok()?;
            registrations.push((id, slot));
            Ok::<_, RclrsError>(())
        };
        let mut view = None;
        {
            match waitable.primitive.handle() {
                RclPrimitiveHandle::Subscription(h) => add(
                    SUBSCRIPTION,
                    (&*h as *const rcl_subscription_t).cast(),
                    ptr::null_mut(),
                )?,
                RclPrimitiveHandle::Timer(h) => add(
                    TIMER_OBSERVER,
                    (&*h as *const rcl_timer_t).cast(),
                    ptr::null_mut(),
                )?,
                RclPrimitiveHandle::Service(h) => add(
                    SERVICE,
                    (&*h as *const rcl_service_t).cast(),
                    ptr::null_mut(),
                )?,
                RclPrimitiveHandle::Client(h) => {
                    add(CLIENT, (&*h as *const rcl_client_t).cast(), ptr::null_mut())?
                }
                RclPrimitiveHandle::Event(h) => {
                    add(EVENT, (&*h as *const rcl_event_t).cast(), ptr::null_mut())?
                }
                RclPrimitiveHandle::GuardCondition(h) => h.use_handle(|h| {
                    add(
                        GUARD_CONDITION,
                        (h as *const rcl_guard_condition_t).cast(),
                        ptr::null_mut(),
                    )
                })?,
                RclPrimitiveHandle::ActionServer(_) | RclPrimitiveHandle::ActionClient(_) => {}
            }
        }
        if matches!(
            waitable.primitive.kind(),
            RclPrimitiveKind::ActionServer | RclPrimitiveKind::ActionClient
        ) {
            let mut ws = WaitSet::new(context)?;
            let mut count = WaitableCount::new();
            count.add_single(&*waitable.primitive);
            unsafe {
                count.resize(&mut ws.handle.rcl_wait_set)?;
            }
            waitable.add_to_wait_set(&mut ws.handle.rcl_wait_set)?;
            let raw = &mut ws.handle.rcl_wait_set;
            let arrays = [
                (
                    SUBSCRIPTION,
                    raw.subscriptions.cast::<*const c_void>(),
                    raw.size_of_subscriptions,
                ),
                (TIMER_OBSERVER, raw.timers.cast(), raw.size_of_timers),
                (SERVICE, raw.services.cast(), raw.size_of_services),
                (CLIENT, raw.clients.cast(), raw.size_of_clients),
                (EVENT, raw.events.cast(), raw.size_of_events),
                (
                    GUARD_CONDITION,
                    raw.guard_conditions.cast(),
                    raw.size_of_guard_conditions,
                ),
            ];
            for (kind, array, count) in arrays {
                for index in 0..count {
                    let slot = unsafe { array.add(index) };
                    let entity = unsafe { *slot };
                    if !entity.is_null() {
                        add(kind, entity, slot)?;
                        unsafe {
                            *slot = ptr::null();
                        }
                    }
                }
            }
            view = Some(ws);
        }
        Ok(Self {
            waitable,
            registrations,
            view,
            worker,
        })
    }

    fn execute(&mut self, payload: &mut dyn Any) -> Result<(), RclrsError> {
        let ready = if let Some(view) = &self.view {
            let raw = &view.handle.rcl_wait_set;
            self.waitable.is_ready(raw)
        } else {
            Some(ReadyKind::Basic)
        };
        if let Some(ready) = ready {
            unsafe {
                self.waitable.primitive.execute(ready, payload)?;
            }
        }
        Ok(())
    }
}

struct Worker {
    payload: Box<dyn Any + Send>,
    context: Context,
    listeners: Vec<WeakActivityListener>,
}
impl Worker {
    fn activity(&mut self) {
        let listeners = std::mem::take(&mut self.listeners);
        for weak in listeners {
            if let Some(listener) = weak.upgrade() {
                let callback = listener.lock().unwrap().take();
                if let Some(mut callback) = callback {
                    if let ActivityListenerCallback::Listen(listen) = &mut callback {
                        listen(&mut *self.payload);
                    }
                    listener.lock().unwrap().replace(callback);
                }
                self.listeners.push(Arc::downgrade(&listener));
            }
        }
    }
}

enum Command {
    Worker(usize, ExecutorWorkerOptions),
    Waitable(usize, Waitable),
    Payload(usize, PayloadTask),
    Listener(usize, WeakActivityListener),
    Poll(Arc<Task>),
    Wake,
}
#[derive(Clone)]
struct Channel {
    sender: Sender<Command>,
    wake: Arc<Wake>,
    next_worker: Arc<AtomicUsize>,
}
impl Channel {
    fn send(&self, command: Command) {
        if self.sender.send(command).is_ok() {
            Wake::wake_by_ref(&self.wake);
        }
    }
}
impl ExecutorChannel for Channel {
    fn create_worker(&self, options: ExecutorWorkerOptions) -> Arc<dyn WorkerChannel> {
        let worker = self.next_worker.fetch_add(1, Ordering::Relaxed);
        self.send(Command::Worker(worker, options));
        Arc::new(WorkerSender {
            worker,
            channel: self.clone(),
        })
    }
    fn wake_all_wait_sets(&self) {
        self.send(Command::Wake);
    }
}
struct WorkerSender {
    worker: usize,
    channel: Channel,
}
impl WorkerChannel for WorkerSender {
    fn add_async_task(&self, future: BoxFuture<'static, ()>) {
        let task = Arc::new(Task {
            future: Mutex::new(Some(future)),
            channel: self.channel.clone(),
        });
        self.channel.send(Command::Poll(task));
    }
    fn add_to_wait_set(&self, waitable: Waitable) {
        self.channel.send(Command::Waitable(self.worker, waitable));
    }
    fn send_payload_task(&self, task: PayloadTask) {
        self.channel.send(Command::Payload(self.worker, task));
    }
    fn add_activity_listener(&self, listener: WeakActivityListener) {
        self.channel.send(Command::Listener(self.worker, listener));
    }
}
struct Task {
    future: Mutex<Option<BoxFuture<'static, ()>>>,
    channel: Channel,
}
impl ArcWake for Task {
    fn wake_by_ref(this: &Arc<Self>) {
        this.channel.send(Command::Poll(this.clone()));
    }
}

/// A single-threaded async runtime driven by the installed rcl executor core.
/// Enable the `rcl_executor` feature and pass this to [`Context::create_executor`].
pub struct RclExecutorRuntime {
    core: Core,
    channel: Channel,
    receiver: Receiver<Command>,
    workers: BTreeMap<usize, Worker>,
    entries: BTreeMap<u64, Entry>,
    registration_entries: BTreeMap<u64, u64>,
    promise: Option<crate::Promise<()>>,
    stale_promises: Vec<crate::Promise<()>>,
}
impl RclExecutorRuntime {
    /// Create a runtime using the C ABI shared executor.
    pub fn new() -> Result<Self, RclrsError> {
        let mut core = ptr::null_mut();
        unsafe { rcl_executor_create(&mut core) }.ok()?;
        let wake = Arc::new(Wake(unsafe { rcl_executor_get_handle(core) }));
        let (sender, receiver) = channel();
        Ok(Self {
            core: Core(core),
            channel: Channel {
                sender,
                wake,
                next_worker: Arc::new(AtomicUsize::new(0)),
            },
            receiver,
            workers: BTreeMap::new(),
            entries: BTreeMap::new(),
            registration_entries: BTreeMap::new(),
            promise: None,
            stale_promises: Vec::new(),
        })
    }

    fn commands(&mut self) -> Result<(bool, bool), RclrsError> {
        let mut pending = true;
        let mut woken = false;
        for _ in 0..256 {
            let Ok(command) = self.receiver.try_recv() else {
                pending = false;
                break;
            };
            match command {
                Command::Wake => woken = true,
                Command::Worker(id, options) => {
                    self.workers.insert(
                        id,
                        Worker {
                            payload: options.payload,
                            context: options.context,
                            listeners: Vec::new(),
                        },
                    );
                }
                Command::Waitable(worker, waitable) => {
                    let entry =
                        Entry::new(&self.core, waitable, worker, &self.workers[&worker].context)?;
                    let key = entry.registrations[0].0;
                    for (id, _) in &entry.registrations {
                        self.registration_entries.insert(*id, key);
                    }
                    self.entries.insert(key, entry);
                }
                Command::Payload(id, task) => {
                    task(&mut *self.workers.get_mut(&id).unwrap().payload)
                }
                Command::Listener(id, listener) => {
                    self.workers.get_mut(&id).unwrap().listeners.push(listener)
                }
                Command::Poll(task) => {
                    let mut future_slot = task.future.lock().unwrap();
                    if let Some(mut future) = future_slot.take() {
                        let waker = waker_ref(&task);
                        if future
                            .as_mut()
                            .poll(&mut TaskContext::from_waker(&waker))
                            .is_pending()
                        {
                            *future_slot = Some(future);
                        }
                    }
                }
            }
        }
        let removed: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, entry)| !entry.waitable.in_use())
            .map(|(id, _)| *id)
            .collect();
        for key in removed {
            for (id, _) in &self.entries[&key].registrations {
                unsafe { rcl_executor_remove(self.core.0, *id) }.ok()?;
                self.registration_entries.remove(id);
            }
            self.entries.remove(&key);
        }
        Ok((pending, woken))
    }

    fn run(&mut self, mut conditions: SpinConditions) -> Result<(), RclrsError> {
        self.promise = conditions.options.until_promise_resolved.take();
        let deadline = conditions
            .options
            .timeout
            .map(|timeout| Instant::now() + timeout);
        let wake = self.channel.wake.clone();
        let waker = waker_ref(&wake);
        let mut task_context = TaskContext::from_waker(&waker);
        let mut first = true;
        loop {
            let (commands_pending, woken) = self.commands()?;
            self.stale_promises
                .retain_mut(|promise| promise.poll_unpin(&mut task_context).is_pending());
            if conditions.halt_spinning.load(Ordering::Acquire) || !conditions.context.ok() {
                return Ok(());
            }
            if let Some(promise) = &mut self.promise {
                if promise.poll_unpin(&mut task_context).is_ready() {
                    self.promise = None;
                    return Ok(());
                }
            }
            if !first && deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(RclrsError::RclError {
                    code: RclReturnCode::Timeout,
                    msg: None,
                });
            }
            let mut dispatched = Vec::new();
            for _ in 0..256 {
                let mut item = Item::default();
                let result = unsafe {
                    rcl_executor_next_excluding(
                        self.core.0,
                        &mut item,
                        dispatched.as_ptr(),
                        dispatched.len(),
                    )
                };
                if result == ERROR {
                    return 1_i32.ok();
                }
                if result != READY {
                    break;
                }
                let _claim = Claim {
                    core: self.core.0,
                    token: item.token,
                };
                let key = self.registration_entries[&item.registration];
                let entry = self.entries.get_mut(&key).unwrap();
                let worker = self.workers.get_mut(&entry.worker).unwrap();
                // Action readiness slots point into the entry's stable native wait-set allocation.
                if let Some((_, slot)) = entry
                    .registrations
                    .iter()
                    .find(|(id, _)| *id == item.registration)
                {
                    if !slot.is_null() {
                        unsafe {
                            **slot = item.entity;
                        }
                    }
                }
                let result = entry.execute(&mut *worker.payload);
                for (_, slot) in &entry.registrations {
                    if !slot.is_null() {
                        unsafe {
                            **slot = ptr::null();
                        }
                    }
                }
                result?;
                worker.activity();
                dispatched.push(item.registration);
            }
            if !dispatched.is_empty() {
                self.commands()?;
                if conditions.options.only_next_available_work {
                    return Ok(());
                }
                first = false;
                continue;
            }
            if woken && conditions.options.only_next_available_work {
                return Ok(());
            }
            if commands_pending {
                first = false;
                continue;
            }
            let ns = deadline
                .map(|end| {
                    end.saturating_duration_since(Instant::now())
                        .as_nanos()
                        .min(i64::MAX as u128) as i64
                })
                .unwrap_or(-1);
            if unsafe { rcl_executor_wait(self.core.0, ns) } == ERROR {
                return 1_i32.ok();
            }
            first = false;
        }
    }
}
impl Drop for RclExecutorRuntime {
    fn drop(&mut self) {
        for entry in self.entries.values() {
            for (id, _) in &entry.registrations {
                unsafe { rcl_executor_remove(self.core.0, *id) }
                    .ok()
                    .unwrap();
            }
        }
    }
}
impl ExecutorRuntime for RclExecutorRuntime {
    fn channel(&self) -> Arc<dyn ExecutorChannel> {
        Arc::new(self.channel.clone())
    }
    fn spin(&mut self, conditions: SpinConditions) -> Vec<RclrsError> {
        let result = self.run(conditions);
        if let Some(promise) = self.promise.take() {
            self.stale_promises.push(promise);
        }
        result.err().into_iter().collect()
    }
    fn spin_async(
        mut self: Box<Self>,
        conditions: SpinConditions,
    ) -> BoxFuture<'static, (Box<dyn ExecutorRuntime>, Vec<RclrsError>)> {
        let (sender, receiver) = oneshot::channel();
        std::thread::spawn(move || {
            let result = self.spin(conditions);
            sender.send((self as Box<dyn ExecutorRuntime>, result)).ok();
        });
        Box::pin(async move {
            receiver
                .await
                .expect("Shared executor spin thread did not return")
        })
    }
}
impl Context {
    /// Create an executor backed by the installed C ABI shared executor.
    pub fn create_rcl_executor(&self) -> Result<Executor, RclrsError> {
        Ok(self.create_executor(RclExecutorRuntime::new()?))
    }
}
