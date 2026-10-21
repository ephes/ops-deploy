//! `collect --report-usage` (PLAN.md 3.1, 4.2 item 9, 10): one stderr line
//! with the run's wall time, CPU time and peak memory, for the shadow units
//! (PLAN.md 8.1) and the lean goals (PLAN.md 10).
//!
//! The line is
//! `software-live: usage wall_s=<s> cpu_s=<s> maxrss_kib=<KiB> self_cpu_s=<s>
//! self_maxrss_kib=<KiB> children_cpu_s=<s> children_maxrss_kib=<KiB>`
//! (one line, the fields separated by single spaces): `getrusage` of the
//! process (`RUSAGE_SELF`) and of its waited-for children
//! (`RUSAGE_CHILDREN`: the CPU time of all of them, the peak of the largest
//! one). CPU time is user plus system time. `cpu_s` and `maxrss_kib` are
//! the sums of both: the collector stays resident while its one large
//! child, the APT helper, runs, so the sum of the two peaks is the bound of
//! the run's peak the lean goal "Collector peak (self + children
//! `maxrss`)" names.

use std::time::Duration;

use nix::sys::resource::{Usage, UsageWho, getrusage};
use nix::sys::time::TimeValLike;

/// The usage of the process or of its children.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sample {
    /// User plus system CPU time.
    pub cpu: Duration,
    /// Peak resident set size in KiB.
    pub maxrss_kib: u64,
}

fn duration(micros: i64) -> Duration {
    Duration::from_micros(u64::try_from(micros).unwrap_or(0))
}

impl Sample {
    fn of(usage: &Usage) -> Self {
        let cpu = duration(usage.user_time().num_microseconds())
            + duration(usage.system_time().num_microseconds());
        let raw = u64::try_from(usage.max_rss()).unwrap_or(0);
        // Linux reports `ru_maxrss` in KiB, macOS in bytes.
        let maxrss_kib = if cfg!(target_os = "macos") {
            raw / 1024
        } else {
            raw
        };
        Self { cpu, maxrss_kib }
    }

    /// `getrusage(who)`; zero if the call fails (it cannot for these two).
    pub fn take(who: UsageWho) -> Self {
        getrusage(who)
            .map(|usage| Self::of(&usage))
            .unwrap_or_default()
    }
}

/// The usage line for a run that took `wall`.
pub fn line(wall: Duration, me: Sample, children: Sample) -> String {
    let seconds = |d: Duration| format!("{:.3}", d.as_secs_f64());
    format!(
        "software-live: usage wall_s={} cpu_s={} maxrss_kib={} self_cpu_s={} self_maxrss_kib={} \
         children_cpu_s={} children_maxrss_kib={}",
        seconds(wall),
        seconds(me.cpu + children.cpu),
        me.maxrss_kib + children.maxrss_kib,
        seconds(me.cpu),
        me.maxrss_kib,
        seconds(children.cpu),
        children.maxrss_kib,
    )
}

/// The usage line of this process now, `wall` after its start.
pub fn report(wall: Duration) -> String {
    line(
        wall,
        Sample::take(UsageWho::RUSAGE_SELF),
        Sample::take(UsageWho::RUSAGE_CHILDREN),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_line_sums_self_and_children() {
        let me = Sample {
            cpu: Duration::from_millis(120),
            maxrss_kib: 4096,
        };
        let children = Sample {
            cpu: Duration::from_micros(300_500),
            maxrss_kib: 61_440,
        };
        assert_eq!(
            line(Duration::from_millis(1234), me, children),
            "software-live: usage wall_s=1.234 cpu_s=0.420 maxrss_kib=65536 self_cpu_s=0.120 \
             self_maxrss_kib=4096 children_cpu_s=0.300 children_maxrss_kib=61440"
        );
    }

    #[test]
    fn the_process_has_a_peak_and_the_line_is_one_line() {
        let me = Sample::take(UsageWho::RUSAGE_SELF);
        assert!(me.maxrss_kib > 0);
        let text = report(Duration::from_millis(5));
        assert!(text.starts_with("software-live: usage wall_s=0.005 cpu_s="));
        assert!(!text.contains('\n'));
        assert_eq!(text.split(' ').count(), 9);
    }
}
