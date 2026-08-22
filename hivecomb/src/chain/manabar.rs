//! Mana bars: voting power, downvote power and resource credits.
//!
//! Hive meters three things with the same mechanism. A bar holds a current value and
//! the time it was last updated; it refills linearly to its maximum over
//! [`REGENERATION_SECONDS`] — five days. Spending is instant, refilling is not.
//!
//! The chain does not store the current value; it stores the value at the last update
//! and lets clients extrapolate. So computing "how much voting power do I have right
//! now" is arithmetic, not a query — which is why it lives here rather than in the RPC
//! layer, and why it needs no network access at all.
//!
//! # Care with the maths
//!
//! `current_mana * 100 / max_mana` overflows a 64-bit integer for any real account:
//! VESTS balances routinely exceed 10^14, and multiplying by 100 before dividing
//! overflows at 9.2 * 10^18. beem works in Python, where integers do not overflow, so
//! it never had to think about this. Here the intermediate is done in `i128`.

/// Seconds for a mana bar to refill from empty to full: five days.
pub const REGENERATION_SECONDS: u64 = 432_000;

/// A mana bar as the chain stores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Manabar {
    /// The value at `last_update_time`.
    pub current_mana: i64,
    /// Unix timestamp of the last update.
    pub last_update_time: u64,
}

impl Manabar {
    /// The mana available at `now`, given a maximum.
    ///
    /// Saturates at `max_mana`; a bar cannot overfill. A `now` earlier than the last
    /// update is treated as no elapsed time rather than as negative regeneration.
    pub fn current(&self, max_mana: i64, now: u64) -> i64 {
        if max_mana <= 0 {
            return 0;
        }
        let elapsed = now.saturating_sub(self.last_update_time);
        let regenerated = (i128::from(elapsed.min(REGENERATION_SECONDS)) * i128::from(max_mana)
            / i128::from(REGENERATION_SECONDS)) as i64;
        self.current_mana
            .saturating_add(regenerated)
            .clamp(0, max_mana)
    }

    /// Percentage of the maximum available at `now`, in `0.0..=100.0`.
    pub fn percentage(&self, max_mana: i64, now: u64) -> f64 {
        if max_mana <= 0 {
            return 0.0;
        }
        // The i128 intermediate is the point: `current * 100` overflows i64 for any
        // real VESTS balance.
        let current = i128::from(self.current(max_mana, now));
        (current * 100) as f64 / max_mana as f64
    }

    /// Seconds until the bar is full, or `None` if it already is.
    pub fn seconds_until_full(&self, max_mana: i64, now: u64) -> Option<u64> {
        let current = self.current(max_mana, now);
        if current >= max_mana || max_mana <= 0 {
            return None;
        }
        let missing = i128::from(max_mana - current);
        Some((missing * i128::from(REGENERATION_SECONDS) / i128::from(max_mana)) as u64)
    }

    /// Seconds until the bar reaches `target_percent` of its maximum.
    pub fn seconds_until(&self, max_mana: i64, now: u64, target_percent: f64) -> Option<u64> {
        if max_mana <= 0 || !(0.0..=100.0).contains(&target_percent) {
            return None;
        }
        let target = (max_mana as f64 * target_percent / 100.0) as i64;
        let current = self.current(max_mana, now);
        if current >= target {
            return None;
        }
        let missing = i128::from(target - current);
        Some((missing * i128::from(REGENERATION_SECONDS) / i128::from(max_mana)) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_bar_stays_full() {
        let bar = Manabar {
            current_mana: 1000,
            last_update_time: 0,
        };
        assert_eq!(bar.current(1000, 0), 1000);
        assert_eq!(bar.current(1000, REGENERATION_SECONDS * 10), 1000);
        assert_eq!(bar.percentage(1000, 0), 100.0);
        assert_eq!(bar.seconds_until_full(1000, 0), None);
    }

    #[test]
    fn an_empty_bar_refills_linearly_over_five_days() {
        let bar = Manabar {
            current_mana: 0,
            last_update_time: 0,
        };
        assert_eq!(bar.current(1000, 0), 0);
        assert_eq!(bar.current(1000, REGENERATION_SECONDS / 2), 500);
        assert_eq!(bar.current(1000, REGENERATION_SECONDS), 1000);
        assert_eq!(bar.seconds_until_full(1000, 0), Some(REGENERATION_SECONDS));
    }

    #[test]
    fn refilling_never_exceeds_the_maximum() {
        let bar = Manabar {
            current_mana: 900,
            last_update_time: 0,
        };
        assert_eq!(bar.current(1000, REGENERATION_SECONDS), 1000);
        assert_eq!(bar.current(1000, REGENERATION_SECONDS * 100), 1000);
    }

    #[test]
    fn does_not_overflow_on_a_realistic_vests_balance() {
        // This is the case Python never had to think about: 3.1e14 * 100 is well past
        // i64::MAX, so a naive `current * 100 / max` would wrap.
        let max: i64 = 314_566_314_850_000;
        let bar = Manabar {
            current_mana: max / 2,
            last_update_time: 0,
        };
        let pct = bar.percentage(max, 0);
        assert!((pct - 50.0).abs() < 0.001, "got {pct}");
        assert_eq!(bar.current(max, 0), max / 2);

        // And at the extreme end of what a mana bar can hold.
        let huge = i64::MAX / 2;
        let bar = Manabar {
            current_mana: huge / 2,
            last_update_time: 0,
        };
        let pct = bar.percentage(huge, 0);
        assert!((pct - 50.0).abs() < 0.001, "got {pct}");
    }

    #[test]
    fn a_clock_that_goes_backwards_does_not_drain_the_bar() {
        let bar = Manabar {
            current_mana: 500,
            last_update_time: 1000,
        };
        assert_eq!(bar.current(1000, 0), 500, "no negative regeneration");
    }

    #[test]
    fn seconds_until_a_target_percentage() {
        let bar = Manabar {
            current_mana: 0,
            last_update_time: 0,
        };
        assert_eq!(
            bar.seconds_until(1000, 0, 50.0),
            Some(REGENERATION_SECONDS / 2)
        );
        assert_eq!(
            bar.seconds_until(1000, 0, 100.0),
            Some(REGENERATION_SECONDS)
        );
        // Already past the target.
        let full = Manabar {
            current_mana: 1000,
            last_update_time: 0,
        };
        assert_eq!(full.seconds_until(1000, 0, 50.0), None);
        // Nonsense targets.
        assert_eq!(bar.seconds_until(1000, 0, 101.0), None);
        assert_eq!(bar.seconds_until(1000, 0, -1.0), None);
    }

    #[test]
    fn a_zero_maximum_is_handled_rather_than_dividing_by_zero() {
        let bar = Manabar {
            current_mana: 0,
            last_update_time: 0,
        };
        assert_eq!(bar.current(0, 100), 0);
        assert_eq!(bar.percentage(0, 100), 0.0);
        assert_eq!(bar.seconds_until_full(0, 100), None);
    }

    #[test]
    fn parses_the_shape_the_api_sends() {
        let bar: Manabar = serde_json::from_str(
            r#"{"current_mana": 314566314850, "last_update_time": 1754586540}"#,
        )
        .unwrap();
        assert_eq!(bar.current_mana, 314_566_314_850);
        assert_eq!(bar.last_update_time, 1_754_586_540);
    }
}
