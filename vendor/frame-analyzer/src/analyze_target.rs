/*
 * Copyright (c) 2024 shadow3aaa@gitbub.com
 *
 * This file is part of frame-analyzer-ebpf.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
use std::{
    collections::{HashMap, VecDeque},
    ptr,
    time::Duration,
};

use frame_analyzer_ebpf_common::FrameSignal;

use crate::uprobe::UprobeHandler;

type BufferHistories = HashMap<usize, (u64, VecDeque<Duration>)>;

fn record_event(buffers: &mut BufferHistories, event: FrameSignal) {
    if let Some((timestamp, buffer)) = buffers.get_mut(&event.buffer) {
        let frametime = event.ktime_ns.saturating_sub(*timestamp);
        *timestamp = event.ktime_ns;

        if buffer.len() >= 144 {
            buffer.pop_back();
        }
        buffer.push_front(Duration::from_nanos(frametime));
    } else {
        buffers.insert(event.buffer, (event.ktime_ns, VecDeque::with_capacity(144)));
    }
}

fn latest_frametime(buffers: &BufferHistories) -> Option<Duration> {
    let max_len = buffers
        .values()
        .map(|(_, buffer)| buffer.len())
        .max()
        .unwrap_or_default();
    buffers
        .values()
        .filter(|(_, buffer)| buffer.len() == max_len)
        .min_by_key(|(_, buffer)| buffer.iter().copied().sum::<Duration>())
        .and_then(|(_, buffer)| buffer.front().copied())
}

pub struct AnalyzeTarget {
    pub uprobe: UprobeHandler,
    buffers: BufferHistories,
}

impl AnalyzeTarget {
    pub fn new(uprobe: UprobeHandler) -> Self {
        Self {
            uprobe,
            buffers: HashMap::new(),
        }
    }

    pub fn update(&mut self) -> Option<Duration> {
        let mut ring = self.uprobe.ring().unwrap();
        let mut received = false;

        while let Some(item) = ring.next() {
            received = true;
            record_event(&mut self.buffers, unsafe { trans(&item) });
        }

        if !received {
            return None;
        }

        latest_frametime(&self.buffers)
    }
}

const unsafe fn trans(buf: &[u8]) -> FrameSignal {
    unsafe { ptr::read_unaligned(buf.as_ptr().cast::<FrameSignal>()) }
}

#[cfg(test)]
mod tests {
    use super::{BufferHistories, latest_frametime, record_event};
    use frame_analyzer_ebpf_common::FrameSignal;
    use std::time::Duration;

    #[test]
    fn keeps_real_intervals_when_draining_multiple_events() {
        let mut buffers = BufferHistories::new();
        record_event(&mut buffers, FrameSignal::new(100, 1));
        record_event(&mut buffers, FrameSignal::new(8_000_100, 1));
        record_event(&mut buffers, FrameSignal::new(16_000_100, 1));

        assert_eq!(latest_frametime(&buffers), Some(Duration::from_millis(8)));
        assert_eq!(buffers[&1].1.len(), 2);
    }

    #[test]
    fn selects_the_surface_with_the_most_submissions() {
        let mut buffers = BufferHistories::new();
        record_event(&mut buffers, FrameSignal::new(100, 1));
        record_event(&mut buffers, FrameSignal::new(10_000_100, 1));
        record_event(&mut buffers, FrameSignal::new(20_000_100, 1));
        record_event(&mut buffers, FrameSignal::new(100, 2));
        record_event(&mut buffers, FrameSignal::new(1_000_100, 2));

        assert_eq!(latest_frametime(&buffers), Some(Duration::from_millis(10)));
    }
}
