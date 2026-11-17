//! Thread CPU time (CLOCK_THREAD_CPUTIME_ID), in nanoseconds.
//!
//! The benchmark host runs other jobs outside the heavy-slot lock, so a pinned
//! core is still time-shared. Wall time would then count the time this thread
//! waits for the core. Thread CPU time counts only the time it runs.
#![allow(dead_code)]

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

extern "C" {
    fn clock_gettime(clock: i32, tp: *mut Timespec) -> i32;
}

/// Linux CLOCK_THREAD_CPUTIME_ID (include/uapi/linux/time.h).
const CLOCK_THREAD_CPUTIME_ID: i32 = 3;

/// CPU time of the calling thread in nanoseconds.
pub fn thread_ns() -> u64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid, writable timespec with the 64-bit Linux layout.
    let rc = unsafe { clock_gettime(CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime(CLOCK_THREAD_CPUTIME_ID) failed");
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Milliseconds of thread CPU time since `start` (a `thread_ns` value).
pub fn ms_since(start: u64) -> f64 {
    (thread_ns() - start) as f64 / 1e6
}

/// Criterion measurement over thread CPU time. Values are nanoseconds, so the
/// estimates.json files keep the units of the wall-time measurement.
pub mod criterion_measurement {
    use criterion::measurement::{Measurement, ValueFormatter};
    use criterion::Throughput;

    pub struct ThreadCpu;
    pub struct NsFormatter;

    impl ValueFormatter for NsFormatter {
        fn scale_values(&self, typical: f64, values: &mut [f64]) -> &'static str {
            let (factor, unit) = if typical < 1e3 {
                (1.0, "ns")
            } else if typical < 1e6 {
                (1e-3, "µs")
            } else if typical < 1e9 {
                (1e-6, "ms")
            } else {
                (1e-9, "s")
            };
            for v in values.iter_mut() {
                *v *= factor;
            }
            unit
        }
        fn scale_throughputs(
            &self,
            _typical: f64,
            throughput: &Throughput,
            values: &mut [f64],
        ) -> &'static str {
            let per = match throughput {
                Throughput::Bytes(n) | Throughput::BytesDecimal(n) | Throughput::Elements(n) => {
                    *n as f64
                }
            };
            for v in values.iter_mut() {
                *v = per * 1e9 / *v;
            }
            "units/s (CPU)"
        }
        fn scale_for_machines(&self, _values: &mut [f64]) -> &'static str {
            "ns"
        }
    }

    impl Measurement for ThreadCpu {
        type Intermediate = u64;
        type Value = u64;
        fn start(&self) -> u64 {
            super::thread_ns()
        }
        fn end(&self, start: u64) -> u64 {
            super::thread_ns() - start
        }
        fn add(&self, a: &u64, b: &u64) -> u64 {
            a + b
        }
        fn zero(&self) -> u64 {
            0
        }
        fn to_f64(&self, value: &u64) -> f64 {
            *value as f64
        }
        fn formatter(&self) -> &dyn ValueFormatter {
            &NsFormatter
        }
    }
}
