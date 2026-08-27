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
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Ok, Result, bail};

fn main() -> Result<()> {
    let bpf_linker = install_bpf_linker()?;
    build_ebpf(&bpf_linker)?;
    Ok(())
}
fn find_bpf_linker() -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|directory| directory.join("bpf-linker"))
        .find(|candidate| candidate.is_file())
}

fn install_bpf_linker() -> Result<PathBuf> {
    if let Some(bpf_linker) = find_bpf_linker() {
        return Ok(bpf_linker);
    }

    let out_dir = env::var("OUT_DIR")?;
    let target_dir = Path::new(&out_dir).join("temp_target");
    let target_dir_str = target_dir.to_str().unwrap();
    let host = env::var("HOST")?;

    let status = Command::new("cargo")
        .args([
            "install",
            "bpf-linker",
            "--force",
            "--root",
            target_dir_str,
            "--target-dir",
            target_dir_str,
            "--target",
            &host,
        ])
        .env_remove("CARGO_BUILD_TARGET")
        .status()?;
    if !status.success() {
        bail!("failed to install bpf-linker for host target {host}");
    }

    let bpf_linker = target_dir.join("bin").join("bpf-linker");
    if !bpf_linker.is_file() {
        bail!("bpf-linker was not installed at {}", bpf_linker.display());
    }

    Ok(bpf_linker)
}

fn build_ebpf(bpf_linker: &Path) -> Result<()> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")?;
    let project_path = Path::new(&manifest_dir)
        .parent()
        .unwrap()
        .join("frame-analyzer-ebpf");
    let out_dir = env::var("OUT_DIR")?;
    let out_dir = Path::new(&out_dir);
    let target_dir = out_dir.join("ebpf_target");
    let target_dir_str = target_dir.to_str().unwrap();

    if !target_dir.exists() {
        fs::create_dir(&target_dir)?;
    }

    let mut ebpf_args = vec![
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
        "--target-dir",
        target_dir_str,
    ];

    if project_path.exists() {
        println!("cargo:rerun-if-changed=../frame-analyzer-ebpf");

        #[cfg(not(debug_assertions))]
        ebpf_args.push("--release");

        let status = Command::new("cargo")
            .arg("build")
            .args(ebpf_args)
            .env_remove("RUSTUP_TOOLCHAIN")
            .current_dir(&project_path)
            .env("CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER", bpf_linker)
            .status()?;
        if !status.success() {
            bail!("failed to build local frame-analyzer-ebpf");
        }
    } else {
        #[cfg(debug_assertions)]
        ebpf_args.push("--debug");

        let _ = fs::remove_dir_all(target_dir.join("bin")); // clean up
        let status = Command::new("cargo")
            .args(["install", "frame-analyzer-ebpf"])
            .args(ebpf_args)
            .args(["--root", target_dir_str])
            .env_remove("RUSTUP_TOOLCHAIN")
            .env("CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER", bpf_linker)
            .status()?;
        if !status.success() {
            bail!("failed to install frame-analyzer-ebpf");
        }

        #[cfg(debug_assertions)]
        let prefix_dir = &target_dir.join("bpfel-unknown-none").join("debug");

        #[cfg(not(debug_assertions))]
        let prefix_dir = &target_dir.join("bpfel-unknown-none").join("release");

        let _ = fs::create_dir_all(prefix_dir);
        let to = &prefix_dir.join("frame-analyzer-ebpf");
        fs::rename(target_dir.join("bin").join("frame-analyzer-ebpf"), to)?;
    }

    Ok(())
}
