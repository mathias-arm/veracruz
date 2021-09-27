#![allow(dead_code)]

use crate::ffi::CStr;
use crate::io;
use crate::mem;
use crate::sys::hermit::abi;
use crate::sys::hermit::fast_thread_local::run_dtors;
use crate::time::Duration;

pub type Tid = abi::Tid;

pub struct Thread {
    tid: Tid,
}

unsafe impl Send for Thread {}
unsafe impl Sync for Thread {}

pub const DEFAULT_MIN_STACK_SIZE: usize = 262144;

impl Thread {
    pub unsafe fn new_with_coreid(
        _stack: usize,
        p: Box<dyn FnOnce()>,
        core_id: isize,
    ) -> io::Result<Thread> {
        let p = Box::into_raw(box p);
        let mut tid: Tid = u32::MAX;
        let ret = abi::spawn(
            &mut tid as *mut Tid,
            thread_start,
            &*p as *const _ as *const u8 as usize,
            abi::Priority::into(abi::NORMAL_PRIO),
            core_id,
        );

        return if ret != 0 {
            // The thread failed to start and as a result p was not consumed. Therefore, it is
            // safe to reconstruct the box so that it gets deallocated.
            drop(Box::from_raw(p));
            Err(io::Error::new(io::ErrorKind::Other, "Unable to create thread!"))
        } else {
            Ok(Thread { tid: tid })
        };

        extern "C" fn thread_start(main: usize) {
            unsafe {
                // Finally, let's run some code.
                Box::from_raw(main as *mut Box<dyn FnOnce()>)();

                // run all destructors
                run_dtors();
            }
        }
    }

    pub unsafe fn new(stack: usize, p: Box<dyn FnOnce()>) -> io::Result<Thread> {
        Thread::new_with_coreid(stack, p, -1 /* = no specific core */)
    }

    #[inline]
    pub fn yield_now() {
        unsafe {
            abi::yield_now();
        }
    }

    #[inline]
    pub fn set_name(_name: &CStr) {
        // nope
    }

    #[inline]
    pub fn sleep(dur: Duration) {
        unsafe {
            abi::usleep(dur.as_micros() as u64);
        }
    }

    pub fn join(self) {
        unsafe {
            let _ = abi::join(self.tid);
        }
    }

    #[inline]
    pub fn id(&self) -> Tid {
        self.tid
    }

    #[inline]
    pub fn into_id(self) -> Tid {
        let id = self.tid;
        mem::forget(self);
        id
    }
}

pub mod guard {
    pub type Guard = !;
    pub unsafe fn current() -> Option<Guard> {
        None
    }
    pub unsafe fn init() -> Option<Guard> {
        None
    }
}