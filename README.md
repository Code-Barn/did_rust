# Shared DID Rust Library

A high-performance Rust library for DID (Decentralized Identifier) operations, shared between multiple projects. This library exports C FFI bindings, making it easy to integrate with Python, Node.js, and other languages.

## Features

- **DID Generation**: Generate DIDs using the `did:key` method
- **VC Verification**: Verify Verifiable Credentials
- **VC Issuance**: Issue new Verifiable Credentials
- **FFI Interface**: C-compatible FFI bindings via `extern "C"`
- **WASM Ready**: WebAssembly bindings prepared for browser use

## Building

To build the library, you'll need [Rust and Cargo](https://rustup.rs/) installed.

```bash
cargo build --release
```

This produces the shared libraries in `target/release/`:
- `libdid_rust.so` (Linux)
- `libdid_rust.dylib` (macOS)
- `did_rust.dll` (Windows)
- `libdid_rust.rlib` - Static Rust library

## Quick Start (Python)

The library provides FFI functions that can be easily loaded in Python using `ctypes`. See the [Developer Guide](DID_DEVELOPER_GUIDE.md) for detailed examples on how to write the wrapper safely, ensuring proper memory management.

```python
import ctypes
import os

lib = ctypes.CDLL(os.path.join("path_to_release", "libdid_rust.so"))

# ... configure argtypes and restypes ...
# See DID_DEVELOPER_GUIDE.md for the full wrapper implementation
```

## FFI Functions Reference

| Function | Arguments | Returns | Description |
|----------|-----------|---------|-------------|
| `generate_did_ffi` | `method: *const c_char` | `*mut c_char` | Generates a DID with a new ed25519 keypair. Pass `"key"` or `null` for `did:key`, or `"web:domain.com"` for `did:web` with pre-built document. Returns JSON. Must be freed! |
| `verify_vc_ffi` | `vc: *const c_char` | `*mut c_char` | Verifies a VC JSON string. Returns `{"valid": bool, "error": "...", "details": {}}`. Must be freed! |
| `verify_vp_ffi` | `vp: *const c_char` | `*mut c_char` | Verifies a Verifiable Presentation JSON string (including embedded VCs). Returns `{"valid": bool, "error": "...", "details": {}}`. Must be freed! |
| `issue_vc_ffi` | `credential, did, key: *const c_char` | `*mut c_char` | Issues a new VC by signing with the provided private key. Must be freed! |
| `resolve_did_ffi` | `did: *const c_char` | `*mut c_char` | Resolves a DID to a DID Document (supports `did:key`, `did:web`). Must be freed! |
| `free_string` | `ptr: *mut c_char` | `()` | Frees a C string returned by other FFI functions. |

⚠️ **Memory Management Note**: Any string (`*mut c_char`) returned by the FFI functions **must** be freed by passing it to `free_string` after you are done with it to prevent memory leaks.

## Development

For detailed instructions on architecture, testing, contributing, and writing cross-language wrappers, please read the [Developer Guide](DID_DEVELOPER_GUIDE.md).

## License

MIT
