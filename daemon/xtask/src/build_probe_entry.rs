use std::{path::PathBuf, process::Command};

use crate::build_ebpf_common::{Options};

pub fn build_probe_entry(opts: Options) -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("daemon-probe-entry");
    let target = format!("--target={}", opts.target);
    let mut args = vec!["build", target.as_str(), "-Z", "build-std=core"];
    if opts.release {
        args.push("--release")
    }

    // Command::new creates a child process which inherits all env variables. This means env
    // vars set by the cargo xtask command are also inherited. RUSTUP_TOOLCHAIN is removed
    // so the rust-toolchain.toml file in the -ebpf folder is honored.

    let status = Command::new("cargo")
        .current_dir(dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args(&args)
        .status()
        .expect("failed to build probe_entry bpf program");
    assert!(status.success());
    Ok(())
}
