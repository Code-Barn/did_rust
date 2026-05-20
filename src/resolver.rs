/*
 * Copyright (C) 2026 David Byers dba Byers Brands
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DidDocument {
    pub id: String,
    #[serde(rename = "verificationMethod", default)]
    pub verification_method: Vec<VerificationMethod>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub controller: String,
    #[serde(rename = "publicKeyBase58")]
    pub public_key_base58: Option<String>,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: Option<String>,
}

pub trait DidResolver {
    fn resolve(&self, did: &str) -> Result<DidDocument, String>;
}

pub struct KeyResolver;
impl DidResolver for KeyResolver {
    fn resolve(&self, did: &str) -> Result<DidDocument, String> {
        if !did.starts_with("did:key:z") {
            return Err("Invalid did:key format".into());
        }
        let multibase = &did["did:key:".len()..];
        if !multibase.starts_with('z') {
            return Err("Only base58btc (z) is supported for did:key".into());
        }
        let decoded = bs58::decode(&multibase[1..])
            .into_vec()
            .map_err(|e| e.to_string())?;

        if decoded.len() != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
            return Err("Only Ed25519 keys are supported".into());
        }

        let pub_key_bytes = &decoded[2..];
        let pub_key_b58 = bs58::encode(pub_key_bytes).into_string();

        Ok(DidDocument {
            id: did.to_string(),
            verification_method: vec![VerificationMethod {
                id: format!("{}#keys-1", did),
                type_: "Ed25519VerificationKey2018".to_string(),
                controller: did.to_string(),
                public_key_base58: Some(pub_key_b58),
                public_key_multibase: Some(multibase.to_string()),
            }],
        })
    }
}

#[cfg(feature = "http-resolver")]
mod web_resolver_impl {
    use super::*;
    use once_cell::sync::Lazy;
    use reqwest::blocking::Client;

    static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
        Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to build HTTP client")
    });

    pub fn build_did_web_url(did: &str) -> Result<String, String> {
        let without_prefix = did.strip_prefix("did:web:").ok_or("Not a did:web")?;
        let parts: Vec<&str> = without_prefix.split(':').collect();
        if parts.is_empty() {
            return Err("Invalid did:web".into());
        }
        let domain = parts[0];
        Ok(if parts.len() == 1 {
            format!("https://{}/.well-known/did.json", domain)
        } else {
            let path = parts[1..].join("/");
            format!("https://{}/{}/did.json", domain, path)
        })
    }

    pub fn fetch_did_document(url: &str) -> Result<DidDocument, String> {
        let response = HTTP_CLIENT.get(url).send().map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!("HTTP error {} fetching {}", response.status(), url));
        }
        response.json().map_err(|e| e.to_string())
    }

    pub struct WebResolver;
    impl DidResolver for WebResolver {
        fn resolve(&self, did: &str) -> Result<DidDocument, String> {
            let url = build_did_web_url(did)?;
            fetch_did_document(&url)
        }
    }

    pub fn resolve_web(did: &str) -> Result<DidDocument, String> {
        WebResolver.resolve(did)
    }
}

#[cfg(test)]
#[cfg(feature = "http-resolver")]
mod web_resolver_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn test_build_did_web_url_well_known() {
        let url = web_resolver_impl::build_did_web_url("did:web:example.com").unwrap();
        assert_eq!(url, "https://example.com/.well-known/did.json");
    }

    #[test]
    fn test_build_did_web_url_path() {
        let url = web_resolver_impl::build_did_web_url("did:web:example:user:alice").unwrap();
        assert_eq!(url, "https://example/user/alice/did.json");
    }

    #[test]
    fn test_build_did_web_url_invalid() {
        assert!(web_resolver_impl::build_did_web_url("did:key:zabc").is_err());
    }

    #[test]
    fn test_fetch_did_document_mock_http() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mock_doc = serde_json::json!({
            "id": "did:web:localhost",
            "verificationMethod": [{
                "id": "did:web:localhost#keys-1",
                "type": "Ed25519VerificationKey2018",
                "controller": "did:web:localhost",
                "publicKeyBase58": "8J5gHnFgN7iNfs3vPVnB6Kn3Eq3KxYKTKFmQHMGzqPnH",
                "publicKeyMultibase": "z6MkkJf3fTJFJ1yVPfBLFmK8PHKxYBvGJzQb3nD1JnKj"
            }]
        });

        thread::spawn(move || {
            for stream in listener.incoming() {
                if let Ok(mut s) = stream {
                    let mut buf = [0u8; 4096];
                    let _ = s.read(&mut buf);
                    let body = mock_doc.to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = s.write_all(response.as_bytes());
                    let _ = s.flush();
                }
                break;
            }
        });

        let url = format!("http://127.0.0.1:{}", port);
        let doc = web_resolver_impl::fetch_did_document(&url).unwrap();
        assert_eq!(doc.id, "did:web:localhost");
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.verification_method[0].controller, "did:web:localhost");
    }
}

#[cfg(not(feature = "http-resolver"))]
mod web_resolver_impl {
    pub fn resolve_web(_did: &str) -> Result<super::DidDocument, String> {
        Err("did:web resolution requires the 'http-resolver' feature (not available in WASM target)".into())
    }

    pub fn build_did_web_url(did: &str) -> Result<String, String> {
        Err(format!(
            "did:web URL construction requires 'http-resolver' feature: {}",
            did
        ))
    }
}

#[cfg(feature = "http-resolver")]
pub use web_resolver_impl::build_did_web_url;
#[cfg(not(feature = "http-resolver"))]
pub use web_resolver_impl::build_did_web_url;

pub struct IpfsResolver;
impl DidResolver for IpfsResolver {
    fn resolve(&self, did: &str) -> Result<DidDocument, String> {
        Err(format!(
            "IPFS resolution is not yet implemented for: {}",
            did
        ))
    }
}

pub fn resolve(did: &str) -> Result<DidDocument, String> {
    if did.starts_with("did:key:") {
        KeyResolver.resolve(did)
    } else if did.starts_with("did:web:") {
        web_resolver_impl::resolve_web(did)
    } else if did.starts_with("did:ipfs:") {
        IpfsResolver.resolve(did)
    } else {
        Err(format!("Unsupported DID method: {}", did))
    }
}
