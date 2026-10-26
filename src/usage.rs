use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    pub period: String,
    pub bytes: u64,
}

impl Usage {
    pub fn current(now: SystemTime) -> Self {
        Self { period: period_key(now), bytes: 0 }
    }

    pub fn load(path: &Path, now: SystemTime) -> Self {
        let period = period_key(now);
        let Ok(raw) = std::fs::read(path) else {
            return Self { period, bytes: 0 };
        };
        let Ok(saved) = serde_json::from_slice::<Usage>(&raw) else {
            return Self { period, bytes: 0 };
        };
        if saved.period == period {
            saved
        } else {
            Self { period, bytes: 0 }
        }
    }

    pub fn store(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(self).expect("usage serializes"))?;
        std::fs::rename(tmp, path)
    }
}

pub fn period_key(now: SystemTime) -> String {
    let secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let days = secs / 86_400;
    let s = civil_from_days(days as i64);
    // civil_from_days returns year, month, day
    format!("{:04}-{:02}", s.0, s.1)
}

fn civil_from_days(mut z: i64) -> (i64, u32, u32) {
    z += 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_unix_day() {
        // 2026-10-20 00:00:00 UTC is 1760918400? We only lock the calendar conversion
        // for 1970-01-01.
        assert_eq!(period_key(UNIX_EPOCH), "1970-01");
    }
}
