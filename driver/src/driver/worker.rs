use std::{
    cell::Cell,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use super::{
    frontend::Frontend,
    queue::Queues,
    status::{self, Status},
    usb::{Pipes, UsbTransport},
};

pub(crate) struct Control {
    stop: Arc<AtomicBool>,
    deadline: Cell<Option<Instant>>,
    finalizing: Cell<bool>,
}

impl Control {
    pub(crate) fn stopping(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    #[cfg(feature = "pcsc")]
    pub(crate) fn bound(&self, wait: Duration) {
        self.deadline.set(Some(Instant::now() + wait));
    }

    pub(crate) fn wait_budget(&self, requested: Duration) -> Result<Duration, Status> {
        if self.stopping() && !self.finalizing.get() {
            return Err(Status(status::CANCELLED));
        }
        Ok(self.deadline.get().map_or(requested, |deadline| {
            requested.min(deadline.saturating_duration_since(Instant::now()))
        }))
    }
}

pub(crate) struct Worker {
    thread: JoinHandle<()>,
    stop: Arc<AtomicBool>,
}

impl Worker {
    pub(crate) fn start(
        pipes: Pipes,
        queues: Queues,
        #[cfg(feature = "usb")] release: u16,
        #[cfg(feature = "pcsc")] unit: u32,
    ) -> Result<Self, Status> {
        let stop = Arc::new(AtomicBool::new(false));
        let cancel = Arc::clone(&stop);
        let (ready, startup) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("rcs956-umdf".into())
            .spawn(move || {
                let control = Rc::new(Control {
                    stop: cancel,
                    deadline: Cell::new(None),
                    finalizing: Cell::new(false),
                });
                let transport = UsbTransport::new(pipes, Rc::clone(&control));
                let mut frontend = match Frontend::new(
                    transport,
                    queues,
                    #[cfg(feature = "usb")]
                    release,
                    #[cfg(feature = "pcsc")]
                    unit,
                    Rc::clone(&control),
                ) {
                    Ok(frontend) => frontend,
                    Err(error) => {
                        let _result = ready.send(Err(error));
                        return;
                    }
                };
                if ready.send(Ok(())).is_err() {
                    return;
                }
                frontend.run();
                #[cfg(feature = "pcsc")]
                {
                    control.finalizing.set(true);
                    frontend.shutdown();
                }
            })
            .map_err(|_| Status(status::INSUFFICIENT_RESOURCES))?;
        let worker = Self { thread, stop };
        let result = startup
            .recv()
            .unwrap_or(Err(Status(status::DEVICE_NOT_READY)));
        if let Err(error) = result {
            worker.stop();
            return Err(error);
        }
        Ok(worker)
    }

    pub(crate) fn waker(&self) -> Option<thread::Thread> {
        (!self.thread.is_finished()).then(|| self.thread.thread().clone())
    }

    pub(crate) fn stop(self) {
        self.stop.store(true, Ordering::Release);
        self.thread.thread().unpark();
        if self.thread.join().is_err() {
            super::trace(format_args!("driver worker terminated unexpectedly"));
        }
    }
}
