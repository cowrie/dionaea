// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only
// ABOUTME: Bidirectional stream buffer for recording connection I/O.
// ABOUTME: Thread-safe storage of ordered data chunks with direction metadata.

use std::sync::Mutex;

use bytes::Bytes;

use crate::connection::Direction;

/// Bidirectional stream buffer that records data in both directions.
///
/// Used by the processor pipeline (streamdumper, shellcode detector) to
/// maintain a history of all data transferred on a connection.
pub struct BiStream {
    chunks: Mutex<Vec<StreamChunk>>,
}

/// A single chunk of data with direction and global offset.
#[derive(Debug, Clone)]
pub struct StreamChunk {
    /// Whether this chunk was received or sent.
    pub direction: Direction,
    /// The raw bytes.
    pub data: Bytes,
    /// Cumulative byte offset within this direction's stream.
    pub offset: usize,
}

impl BiStream {
    /// Create an empty bistream.
    pub fn new() -> Self {
        BiStream {
            chunks: Mutex::new(Vec::new()),
        }
    }

    /// Append a chunk of data.
    pub fn push(&self, direction: Direction, data: Bytes) {
        let mut chunks = self.chunks.lock().expect("bistream lock");
        let offset = chunks
            .iter()
            .filter(|c| c.direction == direction)
            .map(|c| c.offset + c.data.len())
            .last()
            .unwrap_or(0);
        chunks.push(StreamChunk {
            direction,
            data,
            offset,
        });
    }

    /// Number of recorded chunks.
    pub fn len(&self) -> usize {
        self.chunks.lock().expect("bistream lock").len()
    }

    /// Whether the bistream has no recorded chunks.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clone all chunks for reading.
    pub fn chunks(&self) -> Vec<StreamChunk> {
        self.chunks.lock().expect("bistream lock").clone()
    }

    /// Total bytes in a given direction.
    pub fn total_bytes(&self, direction: Direction) -> usize {
        let chunks = self.chunks.lock().expect("bistream lock");
        chunks
            .iter()
            .filter(|c| c.direction == direction)
            .map(|c| c.data.len())
            .sum()
    }
}

impl Default for BiStream {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bistream() {
        let bs = BiStream::new();
        assert!(bs.is_empty());
        assert_eq!(bs.len(), 0);
        assert_eq!(bs.total_bytes(Direction::In), 0);
        assert_eq!(bs.total_bytes(Direction::Out), 0);
    }

    #[test]
    fn push_and_read() {
        let bs = BiStream::new();
        bs.push(Direction::In, Bytes::from_static(b"GET / HTTP/1.1\r\n"));
        bs.push(Direction::Out, Bytes::from_static(b"HTTP/1.1 200 OK\r\n"));
        bs.push(Direction::In, Bytes::from_static(b"Host: x\r\n"));

        assert_eq!(bs.len(), 3);
        let chunks = bs.chunks();
        assert_eq!(chunks[0].offset, 0);
        assert_eq!(chunks[0].data, &b"GET / HTTP/1.1\r\n"[..]);
        assert_eq!(chunks[1].offset, 0); // first Out chunk
        assert_eq!(chunks[2].offset, 16); // second In chunk, after 16 bytes
    }

    #[test]
    fn total_bytes_per_direction() {
        let bs = BiStream::new();
        bs.push(Direction::In, Bytes::from_static(b"hello"));
        bs.push(Direction::In, Bytes::from_static(b"world"));
        bs.push(Direction::Out, Bytes::from_static(b"hi"));

        assert_eq!(bs.total_bytes(Direction::In), 10);
        assert_eq!(bs.total_bytes(Direction::Out), 2);
    }

    #[test]
    fn offset_tracking() {
        let bs = BiStream::new();
        bs.push(Direction::In, Bytes::from(vec![0u8; 100]));
        bs.push(Direction::Out, Bytes::from(vec![1u8; 50]));
        bs.push(Direction::In, Bytes::from(vec![2u8; 30]));
        bs.push(Direction::Out, Bytes::from(vec![3u8; 20]));

        let chunks = bs.chunks();
        // In: 0, 100
        assert_eq!(chunks[0].offset, 0);
        assert_eq!(chunks[2].offset, 100);
        // Out: 0, 50
        assert_eq!(chunks[1].offset, 0);
        assert_eq!(chunks[3].offset, 50);
    }
}
