//! eBPF process-exclusion loader and manager (Linux only).
//!
//! This module is the user-space counterpart of `ebpf/src/main.rs`.
//!
//! # How it works (mirrors dae's design)
//!
//! 1. **Load**: the pre-compiled eBPF object (embedded as bytes at compile
//!    time via `include_bytes!`) is loaded into the kernel with `aya`.
//!
//! 2. **cgroup hooks**: six programs are attached to the cgroupv2 root so
//!    that every socket create/connect/sendmsg call by any process on the
//!    system records `cookie → pname` into `COOKIE_PNAME_MAP`.
//!
//! 3. **TC classifier**: a `CgroupSkb`-style TC classifier is attached to the
//!    WAN interface egress.  It checks the socket cookie → pname → exclusion
//!    list and either passes the packet directly (`TC_ACT_OK`, bypassing TUN)
//!    or forwards it to the next action (`TC_ACT_PIPE`, where the TUN redirect
//!    rule picks it up).
//!
//! 4. **exclude_procs_map sync**: `update_excluded_processes()` is called
//!    whenever the configuration changes to keep the BPF map in sync with the
//!    current process exclusion list.
//!
//! # Build
//!
//! The eBPF object must be compiled separately with nightly Rust before the
//! main binary:
//!
//! ```sh
//! cd ebpf
//! cargo +nightly build -Z build-std=core \
//!     --target bpfel-unknown-none --release
//! ```
//!
//! The resulting object is expected at
//! `ebpf/target/bpfel-unknown-none/release/tinytun-ebpf`.
//! It is embedded by the `EBPF_OBJECT_BYTES` constant below.
//!
//! # Feature gate
//!
//! The entire module is compiled only on Linux and only when the `ebpf`
//! Cargo feature is enabled in the root `Cargo.toml`.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use aya::{
    maps::HashMap,
    programs::{CgroupAttachMode, CgroupSock, CgroupSockAddr, SchedClassifier, TcAttachType},
    Ebpf,
};
use log::info;

/// eBPF object bytes embedded at compile time by `build.rs`.
///
/// `build.rs` compiles `ebpf/` with nightly before the main crate is built,
/// so this path is always present when the `ebpf` feature is enabled.
/// The `TINYTUN_EBPF_OBJECT` env-var path (see `load_ebpf_bytes`) still works
/// as an override for development and testing.
static EMBEDDED_EBPF_OBJECT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/ebpf/target/bpfel-unknown-none/release/tinytun-ebpf"
));

/// Return the eBPF object bytes to load into the kernel.
///
/// Resolution order:
///   1. `TINYTUN_EBPF_OBJECT` environment variable — path to a `.o` file on
///      disk.  Useful during development to test a patched object without
///      recompiling the whole binary.
///   2. Bytes embedded at compile time (the normal production path).
fn load_ebpf_bytes() -> Result<Vec<u8>> {
    // 1. Runtime override for development / testing.
    if let Ok(path) = std::env::var("TINYTUN_EBPF_OBJECT") {
        return fs::read(&path)
            .with_context(|| format!("failed to read eBPF object from TINYTUN_EBPF_OBJECT={}", path));
    }

    // 2. Compile-time embedded bytes (built by build.rs).
    Ok(EMBEDDED_EBPF_OBJECT.to_vec())
}

/// Handle to a loaded and attached eBPF process-exclusion program set.
///
/// Dropping this value detaches all programs and unloads the BPF object.
pub struct ProcessExclusionEbpf {
    /// The loaded BPF object. Kept alive so maps and programs remain valid.
    _bpf: Ebpf,
}

impl ProcessExclusionEbpf {
    /// Load and attach the eBPF programs.
    ///
    /// * `cgroup_path` — path to the cgroupv2 mount point (typically
    ///   `/sys/fs/cgroup`).
    /// * `iface` — WAN interface name (e.g. `"eth0"`).
    /// * `excluded_processes` — initial list of process names to exclude.
    pub fn attach(
        cgroup_path: impl AsRef<Path>,
        iface: &str,
        excluded_processes: &[String],
    ) -> Result<Self> {
        let bytes = load_ebpf_bytes()?;
        let mut bpf = Ebpf::load(&bytes)
            .context("failed to load eBPF object")?;

        let cgroup_path = cgroup_path.as_ref();
        let cgroup_file = std::fs::File::open(cgroup_path)
            .with_context(|| format!("failed to open cgroup path {}", cgroup_path.display()))?;

        // ── Attach cgroup/sock_create ─────────────────────────────────────
        {
            let prog: &mut CgroupSock = bpf
                .program_mut("cg_sock_create")
                .context("cg_sock_create not found")?
                .try_into()?;
            prog.load()?;
            prog.attach(&cgroup_file, CgroupAttachMode::default())
                .context("attach cg_sock_create")?;
        }

        // ── Attach cgroup/connect4 ────────────────────────────────────────
        {
            let prog: &mut CgroupSockAddr = bpf
                .program_mut("cg_connect4")
                .context("cg_connect4 not found")?
                .try_into()?;
            prog.load()?;
            prog.attach(&cgroup_file, CgroupAttachMode::default())
                .context("attach cg_connect4")?;
        }

        // ── Attach cgroup/connect6 ────────────────────────────────────────
        {
            let prog: &mut CgroupSockAddr = bpf
                .program_mut("cg_connect6")
                .context("cg_connect6 not found")?
                .try_into()?;
            prog.load()?;
            prog.attach(&cgroup_file, CgroupAttachMode::default())
                .context("attach cg_connect6")?;
        }

        // ── Attach cgroup/sendmsg4 ────────────────────────────────────────
        {
            let prog: &mut CgroupSockAddr = bpf
                .program_mut("cg_sendmsg4")
                .context("cg_sendmsg4 not found")?
                .try_into()?;
            prog.load()?;
            prog.attach(&cgroup_file, CgroupAttachMode::default())
                .context("attach cg_sendmsg4")?;
        }

        // ── Attach cgroup/sendmsg6 ────────────────────────────────────────
        {
            let prog: &mut CgroupSockAddr = bpf
                .program_mut("cg_sendmsg6")
                .context("cg_sendmsg6 not found")?
                .try_into()?;
            prog.load()?;
            prog.attach(&cgroup_file, CgroupAttachMode::default())
                .context("attach cg_sendmsg6")?;
        }

        // ── Attach cgroup/post_bind4 (used for sock_release cleanup) ──────
        {
            let prog: &mut CgroupSock = bpf
                .program_mut("cg_sock_release")
                .context("cg_sock_release not found")?
                .try_into()?;
            prog.load()?;
            prog.attach(&cgroup_file, CgroupAttachMode::default())
                .context("attach cg_sock_release")?;
        }

        // ── Attach TC egress classifier ───────────────────────────────────
        {
            let prog: &mut SchedClassifier = bpf
                .program_mut("tc_egress")
                .context("tc_egress not found")?
                .try_into()?;
            prog.load()?;
            prog.attach(iface, TcAttachType::Egress)
                .context("attach tc_egress")?;
        }

        // ── Populate excluded process names ───────────────────────────────
        {
            let mut map: HashMap<_, [u8; 16], u8> =
                HashMap::try_from(bpf.map_mut("EXCLUDE_PROCS_MAP").context("EXCLUDE_PROCS_MAP not found")?)?;
            for name in excluded_processes {
                let key = pname_to_key(name);
                map.insert(key, 1u8, 0)?;
            }
        }

        info!(
            "eBPF process-exclusion programs attached (cgroup={}, iface={})",
            cgroup_path.display(),
            iface
        );

        Ok(Self { _bpf: bpf })
    }

    /// Replace the excluded-process set in the BPF map with `new_names`.
    ///
    /// This is O(n+m) where n = old entries and m = new entries.
    pub fn update_excluded_processes(&mut self, new_names: &[String]) -> Result<()> {
        let map: HashMap<_, [u8; 16], u8> =
            HashMap::try_from(self._bpf.map_mut("EXCLUDE_PROCS_MAP").context("EXCLUDE_PROCS_MAP not found")?)?;

        // Collect keys to remove (not in new_names).
        let new_keys: std::collections::HashSet<[u8; 16]> =
            new_names.iter().map(|n| pname_to_key(n)).collect();

        let old_keys: Vec<[u8; 16]> = map.keys().filter_map(|r| r.ok()).collect();
        drop(map);

        let mut map: HashMap<_, [u8; 16], u8> =
            HashMap::try_from(self._bpf.map_mut("EXCLUDE_PROCS_MAP").context("EXCLUDE_PROCS_MAP not found")?)?;

        for key in &old_keys {
            if !new_keys.contains(key) {
                let _ = map.remove(key);
            }
        }
        for key in &new_keys {
            map.insert(*key, 1u8, 0)?;
        }

        Ok(())
    }
}

/// Convert a process name string to a NUL-padded 16-byte key.
fn pname_to_key(name: &str) -> [u8; 16] {
    let mut key = [0u8; 16];
    let bytes = name.as_bytes();
    let len = bytes.len().min(15); // leave room for NUL if name fits in 15 bytes
    key[..len].copy_from_slice(&bytes[..len]);
    key
}
