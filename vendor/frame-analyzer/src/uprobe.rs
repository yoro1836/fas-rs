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
    ffi::CString,
    fs, io, mem,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    path::Path,
};

use aya::{
    Ebpf,
    maps::{Array, MapData, RingBuf},
    programs::UProbe,
};
use aya_obj::generated::{AYA_PERF_EVENT_IOC_ENABLE, AYA_PERF_EVENT_IOC_SET_BPF, perf_event_attr};
use object::{Object, ObjectSection, ObjectSymbol};

use crate::{ebpf::load_bpf, error::Result};

const LIBGUI_PATH: &str = "/system/lib64/libgui.so";
const UPROBE_TYPE_PATH: &str = "/sys/bus/event_source/devices/uprobe/type";
const SYMBOL_SINGLE: &str =
    "_ZN7android7Surface16hook_queueBufferEP13ANativeWindowP19ANativeWindowBufferi";
const SYMBOL_BATCH: &str = "_ZN7android7Surface12queueBuffersERKNSt3__16vectorINS0_17BatchQueuedBufferENS1_9allocatorIS3_EEEEPNS2_INS_24SurfaceQueueBufferOutputENS4_IS9_EEEE";
const SYMBOL_FALLBACK: &str = "_ZN7android7Surface11queueBufferEONS_2spINS_13GraphicBufferEEEiPNS_24SurfaceQueueBufferOutputE";
const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 1 << 3;

fn resolve_symbol_offset(path: &Path, symbol_name: &str) -> io::Result<u64> {
    let data = fs::read(path)?;
    let object = object::File::parse(&*data).map_err(io::Error::other)?;
    let symbol = object
        .dynamic_symbols()
        .chain(object.symbols())
        .find(|symbol| symbol.name() == Ok(symbol_name))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, symbol_name.to_owned()))?;
    let section_index = symbol
        .section_index()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "symbol has no section"))?;
    let section = object
        .section_by_index(section_index)
        .map_err(io::Error::other)?;
    let (file_offset, _) = section
        .file_range()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "section has no file range"))?;

    Ok(symbol.address() - section.address() + file_offset)
}

fn uprobe_type() -> io::Result<u32> {
    fs::read_to_string(UPROBE_TYPE_PATH)?
        .trim()
        .parse()
        .map_err(io::Error::other)
}
unsafe fn perf_ioctl(fd: i32, request: libc::c_int, argument: libc::c_int) -> libc::c_int {
    #[cfg(target_os = "android")]
    {
        unsafe { libc::ioctl(fd, request, argument) }
    }
    #[cfg(not(target_os = "android"))]
    {
        unsafe { libc::ioctl(fd, request as libc::c_ulong, argument) }
    }
}

pub struct UprobeHandler {
    bpf: Ebpf,
    perf_events: Vec<OwnedFd>,
}

impl Drop for UprobeHandler {
    fn drop(&mut self) {
        self.perf_events.clear();
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
            perf_events: Vec::new(),
        };
        let event_type = uprobe_type()?;
        let mut attached = false;

        for symbol in [SYMBOL_SINGLE, SYMBOL_BATCH] {
            match resolve_symbol_offset(Path::new(LIBGUI_PATH), symbol) {
                Ok(offset) => {
                    handler.attach_offset(event_type, offset)?;
                    attached = true;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }

        if !attached {
            let offset = resolve_symbol_offset(Path::new(LIBGUI_PATH), SYMBOL_FALLBACK)?;
            handler.attach_offset(event_type, offset)?;
        }

        Ok(handler)
    }

    fn attach_offset(&mut self, event_type: u32, offset: u64) -> Result<()> {
        let path = CString::new(LIBGUI_PATH).unwrap();
        let program_fd = self.get_program()?.fd()?.as_fd().as_raw_fd();
        let mut attr = unsafe { mem::zeroed::<perf_event_attr>() };
        attr.size = mem::size_of::<perf_event_attr>() as u32;
        attr.type_ = event_type;
        attr.__bindgen_anon_3.config1 = path.as_ptr() as u64;
        attr.__bindgen_anon_4.config2 = offset;

        let raw_fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &attr,
                -1,
                0,
                -1,
                PERF_FLAG_FD_CLOEXEC,
            )
        };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let perf_event = unsafe { OwnedFd::from_raw_fd(raw_fd as i32) };

        if unsafe {
            perf_ioctl(
                perf_event.as_raw_fd(),
                AYA_PERF_EVENT_IOC_SET_BPF,
                program_fd,
            )
        } < 0
        {
            return Err(io::Error::last_os_error().into());
        }
        if unsafe { perf_ioctl(perf_event.as_raw_fd(), AYA_PERF_EVENT_IOC_ENABLE, 0) } < 0 {
            return Err(io::Error::last_os_error().into());
        }

        self.perf_events.push(perf_event);
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
