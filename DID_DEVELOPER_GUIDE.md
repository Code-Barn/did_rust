# Developer Guide: did_rust

This guide provides information on how to develop, test, and integrate the `did_rust` library.

## Architecture Overview

`did_rust` is designed as a core logic library written in Rust, which exposes its functionality via a C Foreign Function Interface (FFI) and optional WebAssembly (WASM) bindings. This architecture allows the high-performance Rust code to be called from various other languages like Python, Node.js, and browser runtimes.

### Core Design Principle: Layered API

The library is structured in three layers:

1. **Public Rust API** (e.g., `pub fn generate_did(method: &str) -> Result<String, String>`) — pure Rust functions that contain all business logic. These are the source of truth.
2. **FFI wrappers** (`#[no_mangle] pub extern "C" fn generate_did_ffi(...)`) — thin translation layers that call the Rust API. Zero logic, only C-string marshalling.
3. **WASM wrappers** (`#[wasm_bindgen] pub fn generate_did(method: &str) -> String`) — thin translation layers for browser/JS runtimes. Zero logic, only JS-string marshalling.

This guarantees that FFI, WASM, and direct Rust consumers all execute identical code paths.

### Directory Structure

- `src/`: Contains the Rust source code.
  - `lib.rs`: The main library entry point containing the public Rust API, FFI exports, and WASM wrappers.
  - `resolver.rs`: DID resolution module with a trait-based `DidResolver` interface. Supports `did:key` (local), `did:web` (HTTP, feature-gated), and `did:ipfs` (placeholder).
- `python_wrapper/`: Placeholder for a reusable Python `ctypes` wrapper module.
- `wasm-bindings/`: Placeholder for `wasm-bindgen` wrappers for browser usage.

### Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `http-resolver` | On | Enables `did:web` resolution via `reqwest` (blocking HTTP). Disable for WASM targets. |
| `wasm` | Off | Enables `wasm-bindgen` annotations for WASM compilation. |

Build for WASM:
```bash
wasm-pack build --target web --no-default-features --features wasm
```

Build for native (default):
```bash
cargo build --release
```

### FFI Functions

The library exports six C-compatible functions:

| Function | Arguments | Returns | Description |
|----------|-----------|---------|-------------|
| `generate_did_ffi` | `method: *const c_char` | `*mut c_char` | Generates a DID with a new ed25519 keypair. Pass `"key"` or `null` for `did:key`, or `"web:domain.com"` for `did:web`. Returns JSON with `did`, `private_key_base58`, and for `web` method, a pre-built `did_document`. Must be freed! |
| `verify_vc_ffi` | `vc: *const c_char` | `*mut c_char` | Verifies a Verifiable Credential JSON string. Returns JSON `{"valid": bool, "error": "...", "details": {}}`. Must be freed! |
| `verify_vp_ffi` | `vp: *const c_char` | `*mut c_char` | Verifies a Verifiable Presentation JSON string (including all embedded VCs). Returns JSON `{"valid": bool, "error": "...", "details": {}}`. Must be freed! |
| `issue_vc_ffi` | `credential: *const c_char, did: *const c_char, key: *const c_char` | `*mut c_char` | Signs a credential payload with the provided base58-encoded ed25519 private key and attaches a proof block. Must be freed! |
| `resolve_did_ffi` | `did: *const c_char` | `*mut c_char` | Resolves a DID to a DID Document. Supports `did:key` (local) and `did:web` (HTTP fetch, requires `http-resolver` feature). Must be freed! |
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
- **`WebResolver`**: Resolves `did:web:domain:path` by fetching `https://domain/path/did.json` using a shared `reqwest` blocking client. **Feature-gated** behind `http-resolver` — not available in WASM builds.
- **`IpfsResolver`**: Placeholder — returns an error. Not yet implemented.

The top-level `resolve(did)` function dispatches to the correct resolver based on the DID method prefix.

### Public Rust API

In addition to FFI and WASM, the library exposes a pure Rust API for direct consumption by other Rust crates (via `rlib`):

```rust
pub fn generate_did(method: &str) -> Result<String, String>
pub fn verify_vc(vc_json: &str) -> String
pub fn verify_vp(vp_json: &str) -> String
pub fn issue_vc(credential_json: &str, did: &str, key_b58: &str) -> Result<String, String>
pub fn resolve_did(did_str: &str) -> Result<String, String>
```

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

```bash
cargo build
cargo build --release
```

### Testing

```bash
cargo test
```

The test suite covers: DID generation (key + web), VC issuance + verification, VP verification, expired credential rejection, and invalid JSON handling.

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
            let _ = CString::from_raw(ptr);
        }
    }
}
```

**Security note:** `generate_did_ffi` returns the private key seed in base58 encoding as part of its JSON response. Callers must handle this data securely (e.g., do not log it, store encrypted).

## Migration Guide: Python Wrapper

### Breaking Change: `verify_vc_ffi` Return Type

**Before (v0.1.0):** `verify_vc_ffi` returned a bare `bool`.
```python
lib.verify_vc_ffi.restype = ctypes.c_bool

def verify_vc(vc: str) -> bool:
    return lib.verify_vc_ffi(vc.encode("utf-8"))
```

**After (current):** `verify_vc_ffi` returns `*mut c_char` JSON string.
```python
lib.verify_vc_ffi.restype = ctypes.POINTER(ctypes.c_char)

def verify_vc(vc: str) -> dict:
    ptr = lib.verify_vc_ffi(vc.encode("utf-8"))
    result = _read_c_string(ptr)
    if result is None:
        raise RuntimeError("verify_vc returned null")
    return json.loads(result)
```

### Complete Updated Python Wrapper

Here is the full Python wrapper using `ctypes`, with all return types corrected.

```python
import ctypes
import json
import os
import platform

system = platform.system()
if system == 'Linux':
    lib_name = 'libdid_rust.so'
elif system == 'Darwin':
    lib_name = 'libdid_rust.dylib'
elif system == 'Windows':
    lib_name = 'did_rust.dll'
else:
    raise RuntimeError("Unsupported platform")

lib_path = os.path.join(os.path.dirname(__file__), "..", "target", "release", lib_name)
lib = ctypes.CDLL(lib_path)

# ---- Configure argtypes and restypes ----

lib.generate_did_ffi.argtypes = [ctypes.c_char_p]
lib.generate_did_ffi.restype = ctypes.POINTER(ctypes.c_char)

lib.verify_vc_ffi.argtypes = [ctypes.c_char_p]
lib.verify_vc_ffi.restype = ctypes.POINTER(ctypes.c_char)

lib.verify_vp_ffi.argtypes = [ctypes.c_char_p]
lib.verify_vp_ffi.restype = ctypes.POINTER(ctypes.c_char)

lib.issue_vc_ffi.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.issue_vc_ffi.restype = ctypes.POINTER(ctypes.c_char)

lib.resolve_did_ffi.argtypes = [ctypes.c_char_p]
lib.resolve_did_ffi.restype = ctypes.POINTER(ctypes.c_char)

lib.free_string.argtypes = [ctypes.POINTER(ctypes.c_char)]
lib.free_string.restype = None

# ---- Helper to read and free a C string ----

def _read_c_string(ptr):
    if not ptr:
        return None
    try:
        return ctypes.cast(ptr, ctypes.c_char_p).value.decode("utf-8")
    finally:
        lib.free_string(ptr)

# ---- Pythonic wrapper functions ----

def generate_did(method: str = "key") -> dict:
    """Generate a DID. method='key' or 'web:domain.com'."""
    ptr = lib.generate_did_ffi(method.encode("utf-8"))
    result = _read_c_string(ptr)
    if result is None:
        raise RuntimeError("Failed to generate DID")
    return json.loads(result)

def verify_vc(vc: str) -> dict:
    """Verify a VC. Returns {'valid': bool, 'error': str, 'details': dict}."""
    ptr = lib.verify_vc_ffi(vc.encode("utf-8"))
    result = _read_c_string(ptr)
    if result is None:
        raise RuntimeError("verify_vc returned null")
    return json.loads(result)

def verify_vp(vp: str) -> dict:
    """Verify a VP. Returns {'valid': bool, 'error': str, 'details': dict}."""
    ptr = lib.verify_vp_ffi(vp.encode("utf-8"))
    result = _read_c_string(ptr)
    if result is None:
        raise RuntimeError("verify_vp returned null")
    return json.loads(result)

def issue_vc(credential: str, did: str, key: str) -> str:
    """Issue a VC by signing credential with the given DID and private key."""
    ptr = lib.issue_vc_ffi(
        credential.encode("utf-8"),
        did.encode("utf-8"),
        key.encode("utf-8"),
    )
    result = _read_c_string(ptr)
    if result is None:
        raise RuntimeError("Failed to issue VC")
    return result

def resolve_did(did: str) -> dict:
    """Resolve a DID to a DID Document."""
    ptr = lib.resolve_did_ffi(did.encode("utf-8"))
    result = _read_c_string(ptr)
    if result is None:
        raise RuntimeError("Failed to resolve DID")
    return json.loads(result)
```

### Usage Example

```python
# Generate a did:key
info = generate_did("key")
print(info["did"])  # did:key:z...

# Issue a VC
vc = issue_vc(
    json.dumps({"credentialSubject": {"id": "did:example:123"}}),
    info["did"],
    info["private_key_base58"],
)

# Verify (now returns dict instead of bool)
result = verify_vc(vc)
if result["valid"]:
    print("VC is valid")
else:
    print(f"VC verification failed: {result['error']}")
```

## WASM Build & Usage

Building for browser/WASM:

```bash
wasm-pack build --target web --no-default-features --features wasm
```

This produces a `.wasm` file and JavaScript glue in `pkg/`. The WASM build excludes `reqwest` (blocking HTTP is unavailable in browsers), so `did:web` resolution is not supported — only `did:key` resolution works.

### WASM API

```javascript
import { generate_did, verify_vc, verify_vp, issue_vc, resolve_did } from "./pkg/did_rust.js";

const info = JSON.parse(generate_did("key"));
console.log(info.did);  // did:key:z...
```

All WASM functions return JSON strings, identical in schema to the FFI and Rust API.

## Security Considerations

- `generate_did_ffi` returns the private key in its JSON output — treat the returned string as sensitive data
- Verification functions (`verify_vc`, `verify_vp`) return structured JSON with error information for audit trails
- FFI functions are not thread-safe with respect to memory management — each call's returned pointer must be freed exactly once via `free_string`
- In WASM builds, `did:web` resolution is unavailable (use `did:key` only)

## Contributing

1. Ensure your Rust code is formatted: `cargo fmt`
2. Run tests locally before pushing: `cargo test`
3. Ensure no linting errors: `cargo clippy`
4. Update both FFI and WASM wrappers when adding new functionality
