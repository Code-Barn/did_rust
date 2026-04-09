# Shared DID Rust Library

A high-performance Rust library for DID (Decentralized Identifier) operations, shared between Polly and namechart.

## Features

- **DID Generation**: Generate DIDs using the `did:key` method
- **VC Verification**: Verify Verifiable Credentials
- **VC Issuance**: Issue new Verifiable Credentials
- **FFI Interface**: Python bindings via ctypes
- **WASM Ready**: WebAssembly bindings prepared for browser use

## Building

```bash
cargo build --release
```

This produces:
- `target/release/libdid_rust.so` - FFI library for Python
- `target/release/libdid_rust.a` - Static library

## FFI Functions

| Function | Arguments | Returns | Description |
|----------|-----------|---------|-------------|
| `generate_did_ffi` | `method: *const c_char` | `*mut c_char` | Generate DID |
| `verify_vc_ffi` | `vc: *const c_char` | `bool` | Verify VC |
| `issue_vc_ffi` | `credential, did, key: *const c_char` | `*mut c_char` | Issue VC |
| `free_string` | `ptr: *mut c_char` | `()` | Free C string |

## Python Integration

Used by both Polly and namechart via the `did_rust_wrapper` module:

```python
# Polly
from apps.accounts.did_rust_wrapper import generate_did, verify_vc

# namechart
from apps.users.did_rust_wrapper import generate_did, verify_vc
```

## Environment Variables

```bash
# Use Rust backend (recommended)
DID_BACKEND=rust python manage.py runserver

# Use Python backend (fallback)
DID_BACKEND=python python manage.py runserver
```

## Architecture

```
did_rust/
├── Cargo.toml           # Project manifest
├── src/
│   └── lib.rs           # FFI implementations
├── python_wrapper/       # Python FFI helper
├── wasm-bindings/        # WASM for web
└── target/release/
    └── libdid_rust.so   # Built library
```

## Dependencies

- Rust 1.70+
- `cc` crate for C FFI
- Standard library only (no external dependencies)

## License

MIT
