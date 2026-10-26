#[derive(Debug, Clone)]
pub struct Candidate {
    pub index: usize,
    pub remaining: u64,
    pub rtt_ms: Option<u32>,
}

/// Prefer relays that still have quota. Weight by remaining bytes.
/// `ticket` is any non-zero-range random value; selection is deterministic for a given ticket.
pub fn pick(mut candidates: Vec<Candidate>, ticket: u64, max_rtt_ms: u32) -> Option<usize> {
    candidates.retain(|item| item.remaining > 0 && item.rtt_ms.map(|rtt| rtt <= max_rtt_ms).unwrap_or(true));
    let total: u128 = candidates.iter().map(|item| u128::from(item.remaining)).sum();
    if total == 0 {
        return None;
    }
    let mut cursor = u128::from(ticket) % total;
    for item in candidates {
        let weight = u128::from(item.remaining);
        if cursor < weight {
            return Some(item.index);
        }
        cursor -= weight;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_empty_and_slow() {
        let picked = pick(
            vec![
                Candidate { index: 0, remaining: 0, rtt_ms: Some(10) },
                Candidate { index: 1, remaining: 100, rtt_ms: Some(900) },
                Candidate { index: 2, remaining: 50, rtt_ms: Some(80) },
            ],
            1,
            200,
        );
        assert_eq!(picked, Some(2));
    }

    #[test]
    fn weights_follow_remaining() {
        let candidates = vec![
            Candidate { index: 0, remaining: 10, rtt_ms: Some(10) },
            Candidate { index: 1, remaining: 90, rtt_ms: Some(10) },
        ];
        assert_eq!(pick(candidates.clone(), 0, 200), Some(0));
        assert_eq!(pick(candidates, 10, 200), Some(1));
    }
}
