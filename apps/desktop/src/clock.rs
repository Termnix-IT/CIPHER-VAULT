use std::time::{Duration, Instant, SystemTime};

/// Both clocks, because each one misses something: the monotonic clock can pause during
/// suspend, and the wall clock can be moved by the user.
#[derive(Clone, Copy)]
pub struct Stamp {
    pub monotonic: Instant,
    pub wall: SystemTime,
}

impl Stamp {
    pub fn now() -> Self {
        Self { monotonic: Instant::now(), wall: SystemTime::now() }
    }

    /// The larger elapsed time since `self`, or None when the wall clock moved backwards.
    pub fn elapsed_at(&self, now: Stamp) -> Option<Duration> {
        let wall = now.wall.duration_since(self.wall).ok()?;
        Some(now.monotonic.saturating_duration_since(self.monotonic).max(wall))
    }
}
