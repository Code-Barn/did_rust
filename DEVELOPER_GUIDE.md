# Developer Guide: did_rust

This guide provides information on how to develop, test, and integrate the `did_rust` library.

## Architecture Overview

`did_rust` is designed as a core logic library written in Rust, which exposes its functionality via a C Foreign Function Interface (FFI). This architecture allows the high-performance Rust code to be called from various other languages like Python, Node.js, and even compiled to WebAssembly (WASM) for frontend use.

### Directory Structure

- `src/`: Contains the Rust source code.
  - `lib.rs`: The main library entry point containing DID/VC/VP logic, data structures, and `#[no_mangle] pub extern "C"` FFI exports.
  - `resolver.rs`: DID resolution module with a trait-based `DidResolver` interface. Supports `did:key` (local), `did:web` (HTTP), and `did:ipfs` (placeholder).
- `python_wrapper/`: Placeholder for a reusable Python `ctypes` wrapper module.
- `wasm-bindings/`: Placeholder for `wasm-bindgen` wrappers for browser usage.

### FFI Functions

The library exports six C-compatible functions:

| Function | Arguments | Returns | Description |
|----------|-----------|---------|-------------|
| `generate_did_ffi` | `method: *const c_char` | `*mut c_char` | Generates a new `did:key` with ed25519 keypair. Returns JSON with `did` and `private_key_base58`. Note: `method` param is unused — always generates `did:key`. |
| `verify_vc_ffi` | `vc: *const c_char` | `bool` | Verifies a Verifiable Credential JSON string. Returns `true` / `false` (no error detail). |
| `verify_vp_ffi` | `vp: *const c_char` | `*mut c_char` | Verifies a Verifiable Presentation JSON string (including all embedded VCs). Returns JSON `{"valid": true/false, "error": "..."}`. |
| `issue_vc_ffi` | `credential: *const c_char, did: *const c_char, key: *const c_char` | `*mut c_char` | Signs a credential payload with the provided base58-encoded ed25519 private key and attaches a proof block. |
| `resolve_did_ffi` | `did: *const c_char` | `*mut c_char` | Resolves a DID to a DID Document. Supports `did:key` (local) and `did:web` (HTTP fetch). |
| `free_string` | `ptr: *mut c_char` | `()` | Deallocates a string previously returned by any other FFI function. |

### DID Resolution

The `resolver` module (`src/resolver.rs`) provides a `DidResolver` trait:

```rust
pub trait DidResolver {
    fn resolve(&self, did: &str) -> Result<DidDocument, String>;
}
```

Three implementations exist:

- **`KeyResolver`**: Local resolution of `did:key:z...` by decoding the multibase-encoded ed25519 public key. No network calls.
- **`WebResolver`**: Resolves `did:web:domain:path` by fetching `https://domain/path/did.json` using a shared `reqwest` blocking client.
- **`IpfsResolver`**: Placeholder — returns an error. Not yet implemented.

The top-level `resolve(did)` function dispatches to the correct resolver based on the DID method prefix.

### Data Structures

```rust
pub struct Proof {
    pub type_: String,
    pub verification_method: String,
    pub signature_value: String,
    pub created: Option<String>,
    pub challenge: Option<String>,
    pub domain: Option<String>,
}

pub struct VerifiablePresentation {
    pub context: Vec<String>,
    pub type_: Vec<String>,
    pub holder: String,
    pub verifiable_credential: Vec<Value>,
    pub proof: Option<Proof>,
}

pub struct DidDocument {
    pub id: String,
    pub verification_method: Vec<VerificationMethod>,
}

pub struct VerificationMethod {
    pub id: String,
    pub type_: String,
    pub controller: String,
    pub public_key_base58: Option<String>,
    pub public_key_multibase: Option<String>,
}
```

## Local Development

### Prerequisites

- [Rust toolchain](https://rustup.rs/) (cargo, rustc)

### Building

To compile the project and produce the dynamic library (`.so`, `.dylib`, or `.dll`):

```bash
cargo build
```

For production use, always build in release mode:

```bash
cargo build --release
```

### Testing

The library includes unit tests within `src/lib.rs`. Run them using:

```bash
cargo test
```

### Linting

```bash
cargo fmt
cargo clippy
```

## FFI and Memory Management

When exposing Rust strings to C/FFI, we use `std::ffi::CString` and `into_raw()`. This transfers ownership of the memory to the caller.

**Crucial:** The calling language (Python, Node, etc.) cannot free memory allocated by Rust using its own garbage collector or standard `free()` function. It must pass the pointer back to Rust to be deallocated.

That's why `did_rust` provides the `free_string` function:

```rust
#[no_mangle]
pub extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr); // Retakes ownership and drops it
        }
    }
}
```

**Security note:** `generate_did_ffi` returns the private key seed in base58 encoding as part of its JSON response. Callers must handle this data securely (e.g., do not log it, store encrypted).

## Creating a Python Wrapper

Here is a complete example of how to wrap the compiled `libdid_rust.so` using Python's `ctypes` library, demonstrating proper memory management for all FFI functions.

```python
import ctypes
import json
import os
import platform

# 1. Load the library
system = platform.system()
if system == 'Linux':
    lib_name = 'libdid_rust.so'
elif system == 'Darwin':
    lib_name = 'libdid_rust.dylib'
elif system == 'Windows':
    lib_name = 'did_rust.dll'
else:
    raise RuntimeError("Unsupported platform")

# Update this path to where your built library resides
lib_path = os.path.join(os.path.dirname(__file__), "..", "target", "release", lib_name)
lib = ctypes.CDLL(lib_path)

# 2. Configure argtypes and restypes

# generate_did_ffi
lib.generate_did_ffi.argtypes = [ctypes.c_char_p]
lib.generate_did_ffi.restype = ctypes.POINTER(ctypes.c_char)

# verify_vc_ffi
lib.verify_vc_ffi.argtypes = [ctypes.c_char_p]
lib.verify_vc_ffi.restype = ctypes.c_bool

# verify_vp_ffi
lib.verify_vp_ffi.argtypes = [ctypes.c_char_p]
lib.verify_vp_ffi.restype = ctypes.POINTER(ctypes.c_char)

# issue_vc_ffi
lib.issue_vc_ffi.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.issue_vc_ffi.restype = ctypes.POINTER(ctypes.c_char)

# resolve_did_ffi
lib.resolve_did_ffi.argtypes = [ctypes.c_char_p]
lib.resolve_did_ffi.restype = ctypes.POINTER(ctypes.c_char)

# free_string
lib.free_string.argtypes = [ctypes.POINTER(ctypes.c_char)]
lib.free_string.restype = None

# 3. Helper to read and free a C string returned by the library
def _read_c_string(ptr):
    if not ptr:
        return None
    try:
        return ctypes.cast(ptr, ctypes.c_char_p).value.decode("utf-8")
    finally:
        lib.free_string(ptr)

# 4. Create Pythonic wrapper functions
def generate_did(method: str = "key") -> dict:
    method_bytes = method.encode("utf-8")
    ptr = lib.generate_did_ffi(method_bytes)
    result = _read_c_string(ptr)
    if result is None:
        raise RuntimeError("Failed to generate DID")
    return json.loads(result)

def verify_vc(vc: str) -> bool:
    vc_bytes = vc.encode("utf-8")
    return lib.verify_vc_ffi(vc_bytes)

def verify_vp(vp: str) -> dict:
    vp_bytes = vp.encode("utf-8")
    ptr = lib.verify_vp_ffi(vp_bytes)
    result = _read_c_string(ptr)
    if result is None:
        raise RuntimeError("Failed to verify VP")
    return json.loads(result)

def issue_vc(credential: str, did: str, key: str) -> str:
    cred_bytes = credential.encode("utf-8")
    did_bytes = did.encode("utf-8")
    key_bytes = key.encode("utf-8")

    ptr = lib.issue_vc_ffi(cred_bytes, did_bytes, key_bytes)
    result = _read_c_string(ptr)
    if result is None:
        raise RuntimeError("Failed to issue VC")
    return result

def resolve_did(did: str) -> dict:
    did_bytes = did.encode("utf-8")
    ptr = lib.resolve_did_ffi(did_bytes)
    result = _read_c_string(ptr)
    if result is None:
        raise RuntimeError("Failed to resolve DID")
    return json.loads(result)
```

## Security Considerations

- `generate_did_ffi` returns the private key in its JSON output — treat the returned string as sensitive data
- `verify_vc_ffi` returns only a `bool` — it does not distinguish between expired, tampered, or malformed VCs
- FFI functions are not thread-safe with respect to memory management — each call's returned pointer must be freed exactly once

## Contributing

1. Ensure your Rust code is formatted: `cargo fmt`
2. Run tests locally before pushing: `cargo test`
3. Ensure no linting errors: `cargo clippy`
