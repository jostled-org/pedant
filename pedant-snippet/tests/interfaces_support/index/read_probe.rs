//! Exact bounded-read behavior at the byte after the ceiling.

use std::io::{Error, ErrorKind, Read};

use pedant_snippet::{CapacityCollection, CodeIntelligenceError, bounded_reader_for_test};

/// A reader that interrupts exactly once at a selected byte offset.
struct InterruptedOnce {
    bytes: &'static [u8],
    position: usize,
    interrupt_at: usize,
    interrupted: bool,
}

impl Read for InterruptedOnce {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if self.position == self.interrupt_at && !self.interrupted {
            self.interrupted = true;
            return Err(Error::from(ErrorKind::Interrupted));
        }
        let remaining = &self.bytes[self.position..];
        let count = remaining.len().min(output.len());
        output[..count].copy_from_slice(&remaining[..count]);
        self.position += count;
        Ok(count)
    }
}

/// An interrupted probe retries, then distinguishes exact from over-ceiling.
#[test]
fn byte_probe_retries_interruption_and_reads_exactly_one_excess() {
    let mut exact = InterruptedOnce {
        bytes: b"four",
        position: 0,
        interrupt_at: 4,
        interrupted: false,
    };
    assert_eq!(bounded_reader_for_test(&mut exact, 4).unwrap(), b"four");

    let mut excess = InterruptedOnce {
        bytes: b"fours",
        position: 0,
        interrupt_at: 4,
        interrupted: false,
    };
    let refusal = bounded_reader_for_test(&mut excess, 4).unwrap_err();
    assert!(matches!(
        refusal,
        CodeIntelligenceError::Capacity {
            collection: CapacityCollection::FileBytes,
            observed: 5,
            limit: 4,
            ..
        }
    ));
}
