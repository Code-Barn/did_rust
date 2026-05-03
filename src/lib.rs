#![allow(clippy::not_unsafe_ptr_arg_deref)]

pub mod resolver;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Serialize, Deserialize)]
pub struct Proof {
    #[serde(rename = "type", default)]
    pub type_: String,
    #[serde(rename = "verificationMethod", default)]
    pub verification_method: String,
    #[serde(rename = "signatureValue")]
    pub signature_value: String,
    pub created: Option<String>,
    pub challenge: Option<String>,
    pub domain: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifiablePresentation {
    #[serde(rename = "@context", default)]
    pub context: Vec<String>,
    #[serde(rename = "type", default)]
    pub type_: Vec<String>,
    #[serde(default)]
    pub holder: String,
    #[serde(rename = "verifiableCredential", default)]
    pub verifiable_credential: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

#[no_mangle]
pub extern "C" fn generate_did_ffi(_method_ptr: *const c_char) -> *mut c_char {
    // Generate a new ed25519 keypair
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let public_key = signing_key.verifying_key();

    // Format as did:key
    // Multicodec ed25519 pubkey prefix is 0xed01
    let mut multicodec = vec![0xed, 0x01];
    multicodec.extend_from_slice(public_key.as_bytes());
    let multibase_z = format!("z{}", bs58::encode(multicodec).into_string());

    let did = format!("did:key:{}", multibase_z);

    // We also want to return the private key so the caller can use it to issue VCs.
    // Let's return a JSON containing both the DID and the base58-encoded private key seed.
    let seed_b58 = bs58::encode(signing_key.to_bytes()).into_string();

    let result = json!({
        "did": did,
        "private_key_base58": seed_b58
    })
    .to_string();

    match CString::new(result) {
        Ok(c) => c.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

fn internal_verify_signature(payload_bytes: &[u8], sig_b58: &str, did: &str) -> Result<(), String> {
    let sig_bytes = bs58::decode(sig_b58)
        .into_vec()
        .map_err(|_| "Invalid base58 signature")?;
    if sig_bytes.len() != 64 {
        return Err("Invalid signature length".into());
    }
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| "Invalid signature format")?;

    let did_doc = resolver::resolve(did).map_err(|e| format!("DID resolution failed: {}", e))?;

    for method in did_doc.verification_method {
        let pub_key_bytes = if let Some(b58) = method.public_key_base58 {
            bs58::decode(b58).into_vec().unwrap_or_default()
        } else if let Some(multibase) = method.public_key_multibase {
            if let Some(stripped) = multibase.strip_prefix('z') {
                let dec = bs58::decode(stripped).into_vec().unwrap_or_default();
                if dec.len() == 34 && dec[0] == 0xed && dec[1] == 0x01 {
                    dec[2..].to_vec()
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        if pub_key_bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&pub_key_bytes);
            if let Ok(verifying_key) = VerifyingKey::from_bytes(&arr) {
                if verifying_key.verify(payload_bytes, &signature).is_ok() {
                    return Ok(());
                }
            }
        }
    }

    Err("Signature verification failed".into())
}

fn internal_verify_vc(mut vc: Value) -> Result<(), String> {
    let proof = if let Value::Object(ref mut map) = vc {
        match map.remove("proof") {
            Some(Value::Object(p_map)) => p_map,
            _ => return Err("Missing proof object".into()),
        }
    } else {
        return Err("VC is not an object".into());
    };

    let issuer_did = match vc.get("issuer").and_then(|i| i.as_str()) {
        Some(did) => did.to_string(),
        None => return Err("Missing issuer DID".into()),
    };

    if let Some(exp) = vc.get("expirationDate").and_then(|e| e.as_str()) {
        if let Ok(exp_time) = DateTime::parse_from_rfc3339(exp) {
            if Utc::now() > exp_time.with_timezone(&Utc) {
                return Err("VC is expired".into());
            }
        }
    }

    let sig_b58 = match proof.get("signatureValue").and_then(|s| s.as_str()) {
        Some(s) => s.to_string(),
        None => return Err("Missing signatureValue".into()),
    };

    let payload_bytes = serde_json::to_vec(&vc).map_err(|_| "Failed to serialize VC payload")?;

    internal_verify_signature(&payload_bytes, &sig_b58, &issuer_did)
        .map_err(|_| "VC Signature Failure".into())
}

#[no_mangle]
pub extern "C" fn verify_vc_ffi(vc_ptr: *const c_char) -> bool {
    if vc_ptr.is_null() {
        return false;
    }

    let vc_cstr = unsafe { CStr::from_ptr(vc_ptr) };
    let vc_str = match vc_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };

    let vc: Value = match serde_json::from_str(vc_str) {
        Ok(v) => v,
        Err(_) => return false,
    };

    internal_verify_vc(vc).is_ok()
}

#[no_mangle]
pub extern "C" fn verify_vp_ffi(vp_ptr: *const c_char) -> *mut c_char {
    if vp_ptr.is_null() {
        let result = json!({"valid": false, "error": "Null pointer"}).to_string();
        return CString::new(result).unwrap().into_raw();
    }

    let vp_str = unsafe { CStr::from_ptr(vp_ptr) }.to_str().unwrap_or("");
    let mut vp_value: Value = match serde_json::from_str(vp_str) {
        Ok(v) => v,
        Err(_) => {
            let result = json!({"valid": false, "error": "Invalid JSON"}).to_string();
            return CString::new(result).unwrap().into_raw();
        }
    };

    // 1. Verify VP Proof
    let proof = if let Value::Object(ref mut map) = vp_value {
        match map.remove("proof") {
            Some(Value::Object(p_map)) => p_map,
            _ => {
                let result = json!({"valid": false, "error": "VP is missing proof"}).to_string();
                return CString::new(result).unwrap().into_raw();
            }
        }
    } else {
        let result = json!({"valid": false, "error": "VP is not an object"}).to_string();
        return CString::new(result).unwrap().into_raw();
    };

    let holder_did = match vp_value.get("holder").and_then(|h| h.as_str()) {
        Some(did) => did.to_string(),
        None => {
            let result = json!({"valid": false, "error": "VP is missing holder DID"}).to_string();
            return CString::new(result).unwrap().into_raw();
        }
    };

    let sig_b58 = match proof.get("signatureValue").and_then(|s| s.as_str()) {
        Some(s) => s.to_string(),
        None => {
            let result =
                json!({"valid": false, "error": "VP proof missing signatureValue"}).to_string();
            return CString::new(result).unwrap().into_raw();
        }
    };

    let payload_bytes = match serde_json::to_vec(&vp_value) {
        Ok(b) => b,
        Err(_) => {
            let result =
                json!({"valid": false, "error": "Failed to serialize VP payload"}).to_string();
            return CString::new(result).unwrap().into_raw();
        }
    };

    if internal_verify_signature(&payload_bytes, &sig_b58, &holder_did).is_err() {
        let result = json!({"valid": false, "error": "VP Signature Failure"}).to_string();
        return CString::new(result).unwrap().into_raw();
    }

    // 2. Iterate through verifiableCredentials and verify them
    let vcs = match vp_value.get("verifiableCredential") {
        Some(Value::Array(arr)) => arr.clone(),
        Some(single_vc @ Value::Object(_)) => vec![single_vc.clone()],
        _ => {
            let result =
                json!({"valid": false, "error": "VP is missing verifiableCredential"}).to_string();
            return CString::new(result).unwrap().into_raw();
        }
    };

    for vc in vcs {
        if let Err(e) = internal_verify_vc(vc) {
            let error_msg = if e == "VC Signature Failure" {
                e
            } else {
                format!("VC Verification Failure: {}", e)
            };
            let result = json!({"valid": false, "error": error_msg}).to_string();
            return CString::new(result).unwrap().into_raw();
        }
    }

    let result = json!({"valid": true}).to_string();
    match CString::new(result) {
        Ok(c) => c.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn resolve_did_ffi(did_ptr: *const c_char) -> *mut c_char {
    if did_ptr.is_null() {
        return ptr::null_mut();
    }

    let did_str = unsafe { CStr::from_ptr(did_ptr) }.to_str().unwrap_or("");
    match resolver::resolve(did_str) {
        Ok(doc) => {
            let result = serde_json::to_string(&doc).unwrap_or_default();
            match CString::new(result) {
                Ok(c) => c.into_raw(),
                Err(_) => ptr::null_mut(),
            }
        }
        Err(e) => {
            let result = json!({"error": e}).to_string();
            match CString::new(result) {
                Ok(c) => c.into_raw(),
                Err(_) => ptr::null_mut(),
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

#[no_mangle]
pub extern "C" fn issue_vc_ffi(
    credential_ptr: *const c_char,
    did_ptr: *const c_char,
    key_ptr: *const c_char,
) -> *mut c_char {
    if credential_ptr.is_null() || did_ptr.is_null() || key_ptr.is_null() {
        return ptr::null_mut();
    }

    let credential_str = unsafe { CStr::from_ptr(credential_ptr) }
        .to_str()
        .unwrap_or("{}");
    let did_str = unsafe { CStr::from_ptr(did_ptr) }.to_str().unwrap_or("");
    let key_str = unsafe { CStr::from_ptr(key_ptr) }.to_str().unwrap_or("");

    let mut vc: Value = match serde_json::from_str(credential_str) {
        Ok(v) => v,
        Err(_) => return ptr::null_mut(),
    };

    // Add issuer
    if let Value::Object(ref mut map) = vc {
        map.insert("issuer".to_string(), Value::String(did_str.to_string()));
    } else {
        return ptr::null_mut();
    }

    let key_bytes = match bs58::decode(key_str).into_vec() {
        Ok(b) => b,
        Err(_) => return ptr::null_mut(),
    };

    if key_bytes.len() != 32 {
        return ptr::null_mut();
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key_bytes);
    let signing_key = SigningKey::from_bytes(&arr);

    // Serialize the payload

    let payload_bytes = serde_json::to_vec(&vc).unwrap_or_default();

    // Sign
    let signature = signing_key.sign(&payload_bytes);
    let sig_b58 = bs58::encode(signature.to_bytes()).into_string();

    // Attach proof
    if let Value::Object(ref mut map) = vc {
        map.insert(
            "proof".to_string(),
            json!({
                "type": "Ed25519Signature2018",
                "verificationMethod": format!("{}#keys-1", did_str),
                "signatureValue": sig_b58
            }),
        );
    }

    let result = vc.to_string();

    match CString::new(result) {
        Ok(c) => c.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_generate_and_verify_vc() {
        let ptr = generate_did_ffi(ptr::null());
        assert!(!ptr.is_null());
        let result = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        let parsed: Value = serde_json::from_str(result).unwrap();

        let did = parsed["did"].as_str().unwrap();
        let priv_key = parsed["private_key_base58"].as_str().unwrap();

        let cred = json!({
            "credentialSubject": { "id": "did:example:123", "degree": "BSc" }
        })
        .to_string();

        let cred_c = CString::new(cred).unwrap();
        let did_c = CString::new(did).unwrap();
        let key_c = CString::new(priv_key).unwrap();

        let vc_ptr = issue_vc_ffi(cred_c.as_ptr(), did_c.as_ptr(), key_c.as_ptr());
        assert!(!vc_ptr.is_null());

        let vc_str = unsafe { CStr::from_ptr(vc_ptr) }.to_str().unwrap();
        println!("VC: {}", vc_str);

        let vc_c = CString::new(vc_str).unwrap();
        let is_valid = verify_vc_ffi(vc_c.as_ptr());
        assert!(is_valid);

        // Test resolution
        let doc_ptr = resolve_did_ffi(did_c.as_ptr());
        assert!(!doc_ptr.is_null());
        let doc_str = unsafe { CStr::from_ptr(doc_ptr) }.to_str().unwrap();
        assert!(doc_str.contains("verificationMethod"));

        free_string(ptr);
        free_string(vc_ptr);
        free_string(doc_ptr);
    }

    #[test]
    fn test_verify_vp() {
        // 1. Generate Issuer (for VC)
        let issuer_info = serde_json::from_str::<Value>(
            unsafe { CStr::from_ptr(generate_did_ffi(ptr::null())) }
                .to_str()
                .unwrap(),
        )
        .unwrap();
        let issuer_did = issuer_info["did"].as_str().unwrap();
        let issuer_key = issuer_info["private_key_base58"].as_str().unwrap();

        // 2. Generate Holder (for VP)
        let holder_info = serde_json::from_str::<Value>(
            unsafe { CStr::from_ptr(generate_did_ffi(ptr::null())) }
                .to_str()
                .unwrap(),
        )
        .unwrap();
        let holder_did = holder_info["did"].as_str().unwrap();
        let holder_key = holder_info["private_key_base58"].as_str().unwrap();

        // 3. Issue a VC
        let cred = json!({
            "credentialSubject": { "id": holder_did, "membership": "Gold" }
        })
        .to_string();

        let vc_str = unsafe {
            CStr::from_ptr(issue_vc_ffi(
                CString::new(cred).unwrap().as_ptr(),
                CString::new(issuer_did).unwrap().as_ptr(),
                CString::new(issuer_key).unwrap().as_ptr(),
            ))
        }
        .to_str()
        .unwrap();
        let vc: Value = serde_json::from_str(vc_str).unwrap();

        // 4. Create VP
        let mut vp = json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "holder": holder_did,
            "verifiableCredential": [vc]
        });

        // 5. Sign VP (Manual sign for test)
        let payload_bytes = serde_json::to_vec(&vp).unwrap();
        let holder_key_bytes = bs58::decode(holder_key).into_vec().unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&holder_key_bytes);
        let signing_key = SigningKey::from_bytes(&arr);
        let signature = signing_key.sign(&payload_bytes);
        let sig_b58 = bs58::encode(signature.to_bytes()).into_string();

        if let Value::Object(ref mut map) = vp {
            map.insert(
                "proof".into(),
                json!({
                    "type": "Ed25519Signature2018",
                    "verificationMethod": format!("{}#keys-1", holder_did),
                    "signatureValue": sig_b58
                }),
            );
        }

        let vp_json = vp.to_string();
        let vp_c = CString::new(vp_json).unwrap();
        let res_ptr = verify_vp_ffi(vp_c.as_ptr());
        let res_str = unsafe { CStr::from_ptr(res_ptr) }.to_str().unwrap();
        let res_val: Value = serde_json::from_str(res_str).unwrap();

        assert!(
            res_val["valid"].as_bool().unwrap(),
            "VP should be valid, error: {:?}",
            res_val["error"]
        );

        free_string(res_ptr);
    }
}
