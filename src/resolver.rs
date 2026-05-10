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

    pub struct WebResolver;
    impl DidResolver for WebResolver {
        fn resolve(&self, did: &str) -> Result<DidDocument, String> {
            let without_prefix = did.strip_prefix("did:web:").ok_or("Not a did:web")?;
            let parts: Vec<&str> = without_prefix.split(':').collect();

            if parts.is_empty() {
                return Err("Invalid did:web".into());
            }

            let domain = parts[0];
            let url = if parts.len() == 1 {
                format!("https://{}/.well-known/did.json", domain)
            } else {
                let path = parts[1..].join("/");
                format!("https://{}/{}/did.json", domain, path)
            };

            let response = HTTP_CLIENT.get(&url).send().map_err(|e| e.to_string())?;
            if !response.status().is_success() {
                return Err(format!(
                    "Failed to fetch did:web from {}: {}",
                    url,
                    response.status()
                ));
            }

            let doc: DidDocument = response.json().map_err(|e| e.to_string())?;
            Ok(doc)
        }
    }

    pub fn resolve_web(did: &str) -> Result<DidDocument, String> {
        WebResolver.resolve(did)
    }
}

#[cfg(not(feature = "http-resolver"))]
mod web_resolver_impl {
    pub fn resolve_web(did: &str) -> Result<super::DidDocument, String> {
        Err("did:web resolution requires the 'http-resolver' feature (not available in WASM target)".into())
    }
}

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
