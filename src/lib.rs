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

fn c_string(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

fn ed25519_multibase(pubkey: &[u8]) -> String {
    let mut multicodec = Vec::with_capacity(2 + pubkey.len());
    multicodec.extend_from_slice(&[0xed, 0x01]);
    multicodec.extend_from_slice(pubkey);
    format!("z{}", bs58::encode(multicodec).into_string())
}

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

fn internal_verify_signature(
    payload_bytes: &[u8],
    sig_b58: &str,
    did: &str,
) -> Result<(), String> {
    let sig_bytes = bs58::decode(sig_b58)
        .into_vec()
        .map_err(|_| "Invalid base58 signature")?;
    if sig_bytes.len() != 64 {
        return Err("Invalid signature length".into());
    }
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|_| "Invalid signature format")?;

    let did_doc =
        resolver::resolve(did).map_err(|e| format!("DID resolution failed: {}", e))?;

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

fn internal_verify_vc(vc: &Value) -> Result<(), String> {
    let proof = vc
        .get("proof")
        .and_then(|p| p.as_object())
        .ok_or_else(|| "Missing proof object".to_string())?;

    let issuer_did = vc
        .get("issuer")
        .and_then(|i| i.as_str())
        .ok_or_else(|| "Missing issuer DID".to_string())?;

    if let Some(exp) = vc.get("expirationDate").and_then(|e| e.as_str()) {
        if let Ok(exp_time) = DateTime::parse_from_rfc3339(exp) {
            if Utc::now() > exp_time.with_timezone(&Utc) {
                return Err("VC is expired".into());
            }
        }
    }

    let sig_b58 = proof
        .get("signatureValue")
        .and_then(|s| s.as_str())
        .ok_or_else(|| "Missing signatureValue".to_string())?;

    let payload_value = {
        let mut map = vc.as_object().cloned().unwrap_or_default();
        map.remove("proof");
        Value::Object(map)
    };

    let payload_bytes =
        serde_json::to_vec(&payload_value).map_err(|_| "Failed to serialize VC payload")?;

    internal_verify_signature(&payload_bytes, sig_b58, issuer_did)
        .map_err(|_| "VC Signature Failure".into())
}

pub fn generate_did(method: &str) -> Result<String, String> {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let public_key = signing_key.verifying_key();
    let seed_b58 = bs58::encode(signing_key.to_bytes()).into_string();

    if let Some(domain) = method
        .strip_prefix("web:")
        .or_else(|| method.strip_prefix("did:web:"))
    {
        if domain.is_empty() {
            return Err("did:web requires a domain, e.g. 'web:example.com'".into());
        }
        let did = format!("did:web:{}", domain);
        let multibase_z = ed25519_multibase(public_key.as_bytes());
        let pub_key_b58 = bs58::encode(public_key.as_bytes()).into_string();
        let doc = json!({
            "id": did,
            "verificationMethod": [{
                "id": format!("{}#keys-1", did),
                "type": "Ed25519VerificationKey2018",
                "controller": did,
                "publicKeyBase58": pub_key_b58,
                "publicKeyMultibase": multibase_z
            }]
        });
        Ok(json!({
            "did": did,
            "private_key_base58": seed_b58,
            "did_document": doc
        })
        .to_string())
    } else {
        let multibase_z = ed25519_multibase(public_key.as_bytes());
        let did = format!("did:key:{}", multibase_z);
        Ok(json!({
            "did": did,
            "private_key_base58": seed_b58
        })
        .to_string())
    }
}

pub fn verify_vc(vc_json: &str) -> String {
    let vc: Value = match serde_json::from_str(vc_json) {
        Ok(v) => v,
        Err(e) => {
            return json!({"valid": false, "error": format!("Invalid JSON: {}", e), "details": {}})
                .to_string()
        }
    };
    match internal_verify_vc(&vc) {
        Ok(()) => json!({"valid": true, "error": "", "details": {}}).to_string(),
        Err(e) => json!({"valid": false, "error": e, "details": {}}).to_string(),
    }
}

pub fn verify_vp(vp_json: &str) -> String {
    let vp_value: Value = match serde_json::from_str(vp_json) {
        Ok(v) => v,
        Err(_) => {
            return json!({"valid": false, "error": "Invalid JSON", "details": {}}).to_string()
        }
    };

    let proof = match vp_value.get("proof").and_then(|p| p.as_object()) {
        Some(p) => p,
        None => {
            return json!({"valid": false, "error": "VP is missing proof", "details": {}})
                .to_string()
        }
    };

    let holder_did = match vp_value.get("holder").and_then(|h| h.as_str()) {
        Some(did) => did,
        None => {
            return json!({"valid": false, "error": "VP is missing holder DID", "details": {}})
                .to_string()
        }
    };

    let sig_b58 = match proof.get("signatureValue").and_then(|s| s.as_str()) {
        Some(s) => s,
        None => {
            return json!({
                "valid": false,
                "error": "VP proof missing signatureValue",
                "details": {}
            })
            .to_string()
        }
    };

    let payload_value = {
        let mut map = vp_value.as_object().cloned().unwrap_or_default();
        map.remove("proof");
        Value::Object(map)
    };
    let payload_bytes = match serde_json::to_vec(&payload_value) {
        Ok(b) => b,
        Err(_) => {
            return json!({
                "valid": false,
                "error": "Failed to serialize VP payload",
                "details": {}
            })
            .to_string()
        }
    };

    if internal_verify_signature(&payload_bytes, sig_b58, holder_did).is_err() {
        return json!({"valid": false, "error": "VP Signature Failure", "details": {}}).to_string();
    }

    let vcs: Vec<Value> = match vp_value.get("verifiableCredential") {
        Some(Value::Array(arr)) => arr.clone(),
        Some(single_vc @ Value::Object(_)) => vec![single_vc.clone()],
        _ => {
            return json!({
                "valid": false,
                "error": "VP is missing verifiableCredential",
                "details": {}
            })
            .to_string()
        }
    };

    for vc in &vcs {
        if let Err(e) = internal_verify_vc(vc) {
            let error_msg = if e == "VC Signature Failure" {
                e
            } else {
                format!("VC Verification Failure: {}", e)
            };
            return json!({"valid": false, "error": error_msg, "details": {}}).to_string();
        }
    }

    json!({"valid": true, "error": "", "details": {}}).to_string()
}

pub fn issue_vc(credential_json: &str, did: &str, key_b58: &str) -> Result<String, String> {
    let mut vc: Value = serde_json::from_str(credential_json)
        .map_err(|_| "Invalid credential JSON".to_string())?;

    vc.as_object_mut()
        .ok_or_else(|| "Credential is not an object".to_string())?
        .insert("issuer".to_string(), Value::String(did.to_string()));

    let key_bytes = bs58::decode(key_b58)
        .into_vec()
        .map_err(|_| "Invalid base58 private key".to_string())?;

    if key_bytes.len() != 32 {
        return Err("Invalid private key length".to_string());
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key_bytes);
    let signing_key = SigningKey::from_bytes(&arr);

    let payload_bytes =
        serde_json::to_vec(&vc).map_err(|_| "Failed to serialize payload".to_string())?;

    let signature = signing_key.sign(&payload_bytes);
    let sig_b58 = bs58::encode(signature.to_bytes()).into_string();

    vc.as_object_mut()
        .ok_or_else(|| "VC is not an object".to_string())?
        .insert(
            "proof".to_string(),
            json!({
                "type": "Ed25519Signature2018",
                "verificationMethod": format!("{}#keys-1", did),
                "signatureValue": sig_b58
            }),
        );

    Ok(vc.to_string())
}

pub fn resolve_did(did_str: &str) -> Result<String, String> {
    match resolver::resolve(did_str) {
        Ok(doc) => serde_json::to_string(&doc).map_err(|e| e.to_string()),
        Err(e) => Ok(json!({"error": e}).to_string()),
    }
}

#[no_mangle]
pub extern "C" fn generate_did_ffi(method_ptr: *const c_char) -> *mut c_char {
    let method = if method_ptr.is_null() {
        ""
    } else {
        unsafe { CStr::from_ptr(method_ptr) }.to_str().unwrap_or("")
    };
    match generate_did(method) {
        Ok(s) => c_string(s),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn verify_vc_ffi(vc_ptr: *const c_char) -> *mut c_char {
    if vc_ptr.is_null() {
        return c_string(
            json!({"valid": false, "error": "Null pointer", "details": {}}).to_string(),
        );
    }
    let vc_str = match unsafe { CStr::from_ptr(vc_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            return c_string(
                json!({"valid": false, "error": "Invalid UTF-8", "details": {}}).to_string(),
            )
        }
    };
    c_string(verify_vc(vc_str))
}

#[no_mangle]
pub extern "C" fn verify_vp_ffi(vp_ptr: *const c_char) -> *mut c_char {
    if vp_ptr.is_null() {
        return c_string(
            json!({"valid": false, "error": "Null pointer", "details": {}}).to_string(),
        );
    }
    let vp_str = match unsafe { CStr::from_ptr(vp_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            return c_string(
                json!({"valid": false, "error": "Invalid UTF-8", "details": {}}).to_string(),
            )
        }
    };
    c_string(verify_vp(vp_str))
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

    match issue_vc(credential_str, did_str, key_str) {
        Ok(s) => c_string(s),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn resolve_did_ffi(did_ptr: *const c_char) -> *mut c_char {
    if did_ptr.is_null() {
        return ptr::null_mut();
    }
    let did_str = unsafe { CStr::from_ptr(did_ptr) }.to_str().unwrap_or("");
    match resolve_did(did_str) {
        Ok(s) => c_string(s),
        Err(_) => ptr::null_mut(),
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

#[cfg(feature = "wasm")]
mod wasm_api {
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    pub fn generate_did(method: &str) -> String {
        match super::generate_did(method) {
            Ok(s) => s,
            Err(e) => serde_json::json!({"error": e}).to_string(),
        }
    }

    #[wasm_bindgen]
    pub fn verify_vc(vc_json: &str) -> String {
        super::verify_vc(vc_json)
    }

    #[wasm_bindgen]
    pub fn verify_vp(vp_json: &str) -> String {
        super::verify_vp(vp_json)
    }

    #[wasm_bindgen]
    pub fn issue_vc(credential_json: &str, did: &str, key_b58: &str) -> String {
        match super::issue_vc(credential_json, did, key_b58) {
            Ok(s) => s,
            Err(e) => serde_json::json!({"error": e}).to_string(),
        }
    }

    #[wasm_bindgen]
    pub fn resolve_did(did: &str) -> String {
        match super::resolve_did(did) {
            Ok(s) => s,
            Err(e) => serde_json::json!({"error": e}).to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_generate_and_verify_vc() {
        let ptr = generate_did_ffi(std::ptr::null());
        assert!(!ptr.is_null());
        let result = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_owned();
        let parsed: Value = serde_json::from_str(&result).unwrap();

        let did = parsed["did"].as_str().unwrap().to_owned();
        let priv_key = parsed["private_key_base58"].as_str().unwrap().to_owned();

        let cred = json!({
            "credentialSubject": { "id": "did:example:123", "degree": "BSc" }
        })
        .to_string();

        let cred_c = CString::new(cred).unwrap();
        let did_c = CString::new(did.clone()).unwrap();
        let key_c = CString::new(priv_key).unwrap();

        let vc_ptr = issue_vc_ffi(cred_c.as_ptr(), did_c.as_ptr(), key_c.as_ptr());
        assert!(!vc_ptr.is_null());

        let vc_str = unsafe { CStr::from_ptr(vc_ptr) }.to_str().unwrap().to_owned();
        println!("VC: {}", vc_str);

        let vc_c = CString::new(vc_str).unwrap();
        let res_ptr = verify_vc_ffi(vc_c.as_ptr());
        assert!(!res_ptr.is_null());
        let res_str = unsafe { CStr::from_ptr(res_ptr) }.to_str().unwrap().to_owned();
        let res: Value = serde_json::from_str(&res_str).unwrap();
        assert!(
            res["valid"].as_bool().unwrap(),
            "VC should be valid, got: {:?}",
            res_str
        );

        let doc_ptr = resolve_did_ffi(did_c.as_ptr());
        assert!(!doc_ptr.is_null());
        let doc_str = unsafe { CStr::from_ptr(doc_ptr) }.to_str().unwrap();
        assert!(doc_str.contains("verificationMethod"));

        free_string(ptr);
        free_string(vc_ptr);
        free_string(res_ptr);
        free_string(doc_ptr);
    }

    #[test]
    fn test_verify_vp() {
        let issuer_info: Value = serde_json::from_str(
            unsafe { CStr::from_ptr(generate_did_ffi(std::ptr::null())) }
                .to_str()
                .unwrap(),
        )
        .unwrap();
        let issuer_did = issuer_info["did"].as_str().unwrap().to_owned();
        let issuer_key = issuer_info["private_key_base58"].as_str().unwrap().to_owned();

        let holder_info: Value = serde_json::from_str(
            unsafe { CStr::from_ptr(generate_did_ffi(std::ptr::null())) }
                .to_str()
                .unwrap(),
        )
        .unwrap();
        let holder_did = holder_info["did"].as_str().unwrap().to_owned();
        let holder_key = holder_info["private_key_base58"].as_str().unwrap().to_owned();

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
        .unwrap()
        .to_owned();
        let vc: Value = serde_json::from_str(&vc_str).unwrap();

        let mut vp = json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "holder": holder_did,
            "verifiableCredential": [vc]
        });

        let payload_bytes = serde_json::to_vec(&vp).unwrap();
        let holder_key_bytes = bs58::decode(&holder_key).into_vec().unwrap();
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
                    "verificationMethod": format!("{}#keys-1", holder_info["did"].as_str().unwrap()),
                    "signatureValue": sig_b58
                }),
            );
        }

        let vp_json = vp.to_string();
        let vp_c = CString::new(vp_json).unwrap();
        let res_ptr = verify_vp_ffi(vp_c.as_ptr());
        let res_str = unsafe { CStr::from_ptr(res_ptr) }.to_str().unwrap().to_owned();
        let res_val: Value = serde_json::from_str(&res_str).unwrap();

        assert!(
            res_val["valid"].as_bool().unwrap(),
            "VP should be valid, error: {:?}",
            res_val["error"]
        );
        assert!(
            res_val.get("details").is_some(),
            "VP response must include details field"
        );

        free_string(res_ptr);
    }

    #[test]
    fn test_generate_did_key_explicit() {
        let method = CString::new("key").unwrap();
        let ptr = generate_did_ffi(method.as_ptr());
        assert!(!ptr.is_null());
        let result = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_owned();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert!(parsed["did"].as_str().unwrap().starts_with("did:key:"));
        assert!(!parsed["private_key_base58"].as_str().unwrap().is_empty());
        free_string(ptr);
    }

    #[test]
    fn test_generate_did_web() {
        let method = CString::new("web:example.com").unwrap();
        let ptr = generate_did_ffi(method.as_ptr());
        assert!(!ptr.is_null());
        let result = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_owned();
        let parsed: Value = serde_json::from_str(&result).unwrap();

        assert_eq!(parsed["did"], "did:web:example.com");
        assert!(!parsed["private_key_base58"].as_str().unwrap().is_empty());
        assert!(parsed["did_document"].is_object());
        assert_eq!(
            parsed["did_document"]["verificationMethod"][0]["controller"],
            "did:web:example.com"
        );

        free_string(ptr);
    }

    #[test]
    fn test_verify_expired_vc() {
        let ptr = generate_did_ffi(std::ptr::null());
        let result = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_owned();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        let did = parsed["did"].as_str().unwrap().to_owned();
        let priv_key = parsed["private_key_base58"].as_str().unwrap().to_owned();

        let cred = json!({
            "credentialSubject": { "id": "did:example:123" },
            "expirationDate": "2020-01-01T00:00:00Z"
        })
        .to_string();

        let vc_ptr = issue_vc_ffi(
            CString::new(cred).unwrap().as_ptr(),
            CString::new(did).unwrap().as_ptr(),
            CString::new(priv_key).unwrap().as_ptr(),
        );
        let vc_str = unsafe { CStr::from_ptr(vc_ptr) }.to_str().unwrap().to_owned();

        let res_ptr = verify_vc_ffi(CString::new(vc_str.as_str()).unwrap().as_ptr());
        let res: Value = serde_json::from_str(
            unsafe { CStr::from_ptr(res_ptr) }.to_str().unwrap(),
        )
        .unwrap();
        assert!(!res["valid"].as_bool().unwrap());
        assert_eq!(res["error"], "VC is expired");

        free_string(ptr);
        free_string(vc_ptr);
        free_string(res_ptr);
    }

    #[test]
    fn test_verify_vc_invalid_json() {
        let vc_str = "not valid json";
        let vc_c = CString::new(vc_str).unwrap();
        let res_ptr = verify_vc_ffi(vc_c.as_ptr());
        let res: Value = serde_json::from_str(
            unsafe { CStr::from_ptr(res_ptr) }.to_str().unwrap(),
        )
        .unwrap();
        assert!(!res["valid"].as_bool().unwrap());
        assert!(res["error"].as_str().unwrap().contains("Invalid JSON"));
        free_string(res_ptr);
    }
}
