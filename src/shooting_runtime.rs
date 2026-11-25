//! The ordinary W95 Max 0034 report-0E runtime fields.
//! Offsets 12 and 16 echo the request and are not device state.
use serde::{Deserialize, Serialize};

const FIELDS: [usize; 10] = [0, 1, 2, 3, 5, 6, 7, 9, 10, 11];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub selected_slot: u8,
    pub payload: [u8; 12],
}

pub fn query(seed: u8) -> [u8; 64] {
    let mut frame = [0; 64];
    frame[..2].copy_from_slice(&[7, 0x0e]);
    frame[8..].fill(seed);
    frame
}

impl Snapshot {
    pub fn decode(request: &[u8; 64], reply: &[u8]) -> Result<Self, String> {
        if request[..8] != query(0)[..8] || reply.len() != 64 {
            return Err("shooting runtime query framing differs".into());
        }
        for index in 0..64 {
            if !(index >= 8 && FIELDS.contains(&(index - 8))) && request[index] != reply[index] {
                return Err("shooting runtime reply changed an unreturned byte".into());
            }
        }
        let mut payload = [0; 12];
        for index in FIELDS {
            payload[index] = reply[8 + index];
        }
        if payload[0] > 7 {
            return Err("shooting slot is outside 0..7".into());
        }
        Ok(Self {
            selected_slot: payload[0],
            payload,
        })
    }

    /// Preserve every returned field; change only the volatile slot selector.
    pub fn select(&self, slot: u8) -> Result<[u8; 64], String> {
        if slot > 7
            || self.payload[0] != self.selected_slot
            || self.payload[4] != 0
            || self.payload[8] != 0
        {
            return Err("invalid runtime snapshot or shooting slot".into());
        }
        let mut frame = [0; 64];
        frame[..3].copy_from_slice(&[7, 0x0e, 0x80]);
        frame[8..20].copy_from_slice(&self.payload);
        frame[8] = slot;
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn seeded_queries_ignore_only_the_two_echoed_payload_holes() {
        let mut snapshots = Vec::new();
        for seed in [0xa5, 0x5a] {
            let request = query(seed);
            let mut reply = request;
            for index in FIELDS {
                reply[index + 8] = index as u8;
            }
            snapshots.push(Snapshot::decode(&request, &reply).unwrap());
            reply[20] ^= 1;
            assert!(Snapshot::decode(&request, &reply).is_err());
            assert!(Snapshot::decode(&request, &request).is_err());
        }
        assert_eq!(snapshots[0], snapshots[1]);
    }
    #[test]
    fn selection_preserves_all_other_returned_fields() {
        let snapshot = Snapshot {
            selected_slot: 0,
            payload: [0, 7, 8, 9, 0, 11, 12, 13, 0, 15, 16, 17],
        };
        let frame = snapshot.select(1).unwrap();
        assert_eq!(&frame[..8], &[7, 0x0e, 0x80, 0, 0, 0, 0, 0]);
        assert_eq!(&frame[9..20], &snapshot.payload[1..]);
        assert_eq!(frame[8], 1);
        assert!(snapshot.select(8).is_err());
    }
}
