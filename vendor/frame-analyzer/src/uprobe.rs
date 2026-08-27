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
    collections::HashSet,
    fs,
    time::{Duration, Instant},
};

use aya::{
    Ebpf,
    maps::{Array, MapData, RingBuf},
    programs::UProbe,
};

use crate::{ebpf::load_bpf, error::Result};
const LIBGUI_PATH: &str = "/system/lib64/libgui.so";
const SYMBOL_SINGLE: &str =
    "_ZN7android7Surface16hook_queueBufferEP13ANativeWindowP19ANativeWindowBufferi";
const SYMBOL_BATCH: &str = "_ZN7android7Surface12queueBuffersERKNSt3__16vectorINS0_17BatchQueuedBufferENS1_9allocatorIS3_EEEEPNS2_INS_24SurfaceQueueBufferOutputENS4_IS9_EEEE";
const SYMBOL_FALLBACK: &str = "_ZN7android7Surface11queueBufferEONS_2spINS_13GraphicBufferEEEiPNS_24SurfaceQueueBufferOutputE";
const THREAD_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
fn thread_ids(pid: i32) -> std::io::Result<Vec<i32>> {
    let tids = fs::read_dir(format!("/proc/{pid}/task"))?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().to_str()?.parse::<i32>().ok())
        .collect();
    Ok(tids)
}

pub struct UprobeHandler {
    bpf: Ebpf,
    attached_tids: HashSet<i32>,
    last_thread_refresh: Instant,
}

impl Drop for UprobeHandler {
    fn drop(&mut self) {
        if let Ok(program) = self.get_program() {
            let _ = program.unload();
        }
    }
}

impl UprobeHandler {
    pub fn attach_app(pid: i32) -> Result<Self> {
        let mut bpf = load_bpf()?;
        {
            let mut target_tgid = Array::<_, u32>::try_from(bpf.map_mut("TARGET_TGID").unwrap())?;
            target_tgid.set(0, pid as u32, 0)?;
        }

        let program: &mut UProbe = bpf.program_mut("frame_analyzer_ebpf").unwrap().try_into()?;
        program.load()?;

        let mut handler = Self {
            bpf,
            attached_tids: HashSet::new(),
            last_thread_refresh: Instant::now(),
        };
        handler.attach_thread(pid)?;
        handler.refresh_threads_inner(pid)?;
        Ok(handler)
    }

    pub fn refresh_threads(&mut self, pid: i32) -> Result<()> {
        if self.last_thread_refresh.elapsed() < THREAD_REFRESH_INTERVAL {
            return Ok(());
        }

        self.refresh_threads_inner(pid)?;
        self.last_thread_refresh = Instant::now();
        Ok(())
    }

    fn refresh_threads_inner(&mut self, pid: i32) -> Result<()> {
        let mut tids = thread_ids(pid)?
            .into_iter()
            .filter(|tid| !self.attached_tids.contains(tid))
            .collect::<Vec<_>>();
        tids.sort_unstable();

        for tid in tids {
            let _ = self.attach_thread(tid);
        }
        Ok(())
    }

    fn attach_thread(&mut self, tid: i32) -> Result<()> {
        {
            let program = self.get_program()?;
            let single_attached = program
                .attach(Some(SYMBOL_SINGLE), 0, LIBGUI_PATH, Some(tid))
                .is_ok();
            let batch_attached = program
                .attach(Some(SYMBOL_BATCH), 0, LIBGUI_PATH, Some(tid))
                .is_ok();

            if !single_attached && !batch_attached {
                program.attach(Some(SYMBOL_FALLBACK), 0, LIBGUI_PATH, Some(tid))?;
            }
        }

        self.attached_tids.insert(tid);
        Ok(())
    }

    pub fn ring(&mut self) -> Result<RingBuf<&mut MapData>> {
        let ring: RingBuf<&mut MapData> = RingBuf::try_from(self.bpf.map_mut("RING_BUF").unwrap())?;
        Ok(ring)
    }

    fn get_program(&mut self) -> Result<&mut UProbe> {
        let program: &mut UProbe = self
            .bpf
            .program_mut("frame_analyzer_ebpf")
            .unwrap()
            .try_into()?;
        Ok(program)
    }
}

#[cfg(test)]
mod tests {
    use super::thread_ids;

    #[test]
    fn reads_current_process_threads() {
        let pid = std::process::id() as i32;
        assert!(thread_ids(pid).unwrap().contains(&pid));
    }
}
