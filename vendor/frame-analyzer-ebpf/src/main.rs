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
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, gen::bpf_ktime_get_ns},
    macros::{map, uprobe},
    maps::{Array, RingBuf},
    programs::ProbeContext,
};

use frame_analyzer_ebpf_common::FrameSignal;

#[map]
static TARGET_TGID: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static DEBUG_COUNTS: Array<u64> = Array::with_max_entries(3, 0);

#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(0x1000, 0);

#[uprobe]
pub fn frame_analyzer_ebpf(ctx: ProbeContext) -> u32 {
    match try_frame_analyzer_ebpf(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn increment_count(index: u32) {
    if let Some(counter) = DEBUG_COUNTS.get_ptr_mut(index) {
        unsafe { *counter = (*counter).wrapping_add(1) };
    }
}

fn try_frame_analyzer_ebpf(ctx: ProbeContext) -> Result<u32, u32> {
    increment_count(0);
    let current_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if TARGET_TGID.get(0).copied() != Some(current_tgid) {
        return Ok(0);
    }
    increment_count(1);

    if let Some(mut entry) = RING_BUF.reserve::<FrameSignal>(0) {
        increment_count(2);
        let ktime_ns = unsafe { bpf_ktime_get_ns() };
        entry.write(FrameSignal::new(ktime_ns, ctx.arg::<usize>(0).unwrap()));
        entry.submit(0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
