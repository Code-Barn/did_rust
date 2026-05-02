# Developer Guide: did_rust

This guide provides information on how to develop, test, and integrate the `did_rust` library.

## Architecture Overview

`did_rust` is designed as a core logic library written in Rust, which exposes its functionality via a C Foreign Function Interface (FFI). This architecture allows the high-performance Rust code to be called from various other languages like Python, Node.js, and even compiled to WebAssembly (WASM) for frontend use.

### Directory Structure

- `src/`: Contains the Rust source code.
  - `lib.rs`: The main library entry point containing the core logic and FFI exported functions (`#[no_mangle] pub extern "C"`).
- `python_wrapper/`: (Placeholder) Intended to house a reusable Python wrapper module.
- `wasm-bindings/`: (Placeholder) Intended to house `wasm-bindgen` wrappers for browser usage.

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

## Creating a Python Wrapper

Here is a complete example of how to wrap the compiled `libdid_rust.so` using Python's `ctypes` library, demonstrating proper memory management.

```python
import ctypes
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

# issue_vc_ffi
lib.issue_vc_ffi.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.issue_vc_ffi.restype = ctypes.POINTER(ctypes.c_char)

# free_string
lib.free_string.argtypes = [ctypes.POINTER(ctypes.c_char)]
lib.free_string.restype = None

# 3. Create Pythonic wrapper functions
def generate_did(method: str) -> str:
    method_bytes = method.encode('utf-8')
    ptr = lib.generate_did_ffi(method_bytes)
    try:
        if not ptr:
            raise RuntimeError("Failed to generate DID")
        return ctypes.cast(ptr, ctypes.c_char_p).value.decode('utf-8')
    finally:
        lib.free_string(ptr) # ALWAYS FREE

def verify_vc(vc: str) -> bool:
    vc_bytes = vc.encode('utf-8')
    return lib.verify_vc_ffi(vc_bytes)

def issue_vc(credential: str, did: str, key: str) -> str:
    cred_bytes = credential.encode('utf-8')
    did_bytes = did.encode('utf-8')
    key_bytes = key.encode('utf-8')
    
    ptr = lib.issue_vc_ffi(cred_bytes, did_bytes, key_bytes)
    try:
        if not ptr:
            raise RuntimeError("Failed to issue VC")
        return ctypes.cast(ptr, ctypes.c_char_p).value.decode('utf-8')
    finally:
        lib.free_string(ptr) # ALWAYS FREE
```

## Contributing

1. Ensure your Rust code is formatted: `cargo fmt`
2. Run tests locally before pushing: `cargo test`
3. Ensure no linting errors: `cargo clippy`
