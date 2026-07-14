# TODO — did_rust (Core DID Library)

**Orchestrated from:** `omni_social` (central hub)
**Last synced:** 2026-07-13

---

## Layer 2 — Security Hardening

- [ ] **[High] SEC-003 — Submodule alignment enforcement:** Add CI check that the commit hash of `did_rust` pinned in both `iyou_idp/crates/did_rust/` and `iyou_home/libs/did_rust/` matches this repo's HEAD. Prevents silent `serde_json` serialization drift between consumer and source.

## Layer 3 — Development

- [ ] Evaluate `crate-type` configuration — currently produces both `cdylib` (for FFI/WASM) and `rlib` (for Rust consumers). Confirm this is intentional.
- [ ] `http-resolver` feature (reqwest) is default — consider making it opt-in to reduce binary size for WASM targets.
- [ ] Review `wasm-bindings/` directory for WASM build health.
- [ ] Python wrapper (`python_wrapper/`) — status and maintenance needs.

---
