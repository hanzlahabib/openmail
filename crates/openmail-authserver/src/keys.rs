//! The authorization server's signing key: ES256 (P-256), generated on first start and kept in
//! the state directory with owner-only permissions. Only the public half is ever published.
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::EncodingKey;
use rcgen::KeyPair;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::Error;

const KEY_FILE: &str = "oauth-signing-key.pem";
/// Uncompressed SEC1 P-256 point: 0x04 || X(32) || Y(32).
const P256_POINT_LEN: usize = 65;

pub struct SigningKey {
    pub kid: String,
    pub encoding: EncodingKey,
    jwks: Vec<u8>,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Load the key from `dir`, creating (mode 0600) it on first use.
    pub fn load_or_create(dir: &Path) -> Result<Self, Error> {
        let path = dir.join(KEY_FILE);
        let pem = match std::fs::read_to_string(&path) {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let pair = KeyPair::generate().map_err(|e| Error::Key(e.to_string()))?;
                let pem = pair.serialize_pem();
                write_private(&path, pem.as_bytes())?;
                pem
            }
            Err(e) => {
                return Err(Error::Key(format!(
                    "reading {}: {}",
                    path.display(),
                    e.kind()
                )));
            }
        };
        let pair = KeyPair::from_pem(&pem).map_err(|e| Error::Key(e.to_string()))?;
        let point = pair.public_key_raw();
        if point.len() != P256_POINT_LEN || point[0] != 4 {
            return Err(Error::Key(
                "signing key is not an uncompressed P-256 key".into(),
            ));
        }
        let (x, y) = (
            URL_SAFE_NO_PAD.encode(&point[1..33]),
            URL_SAFE_NO_PAD.encode(&point[33..]),
        );
        // RFC 7638 thumbprint as the key id: stable and derived from the public key only.
        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        let kid = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
        let jwks = serde_json::to_vec(&json!({"keys": [{
            "kty": "EC", "crv": "P-256", "x": x, "y": y,
            "use": "sig", "alg": "ES256", "kid": kid,
        }]}))
        .map_err(|e| Error::Key(e.to_string()))?;
        let encoding =
            EncodingKey::from_ec_pem(pem.as_bytes()).map_err(|e| Error::Key(e.to_string()))?;
        Ok(Self {
            kid,
            encoding,
            jwks,
        })
    }

    /// Public key set for the `jwks_uri` document.
    pub fn jwks_json(&self) -> &[u8] {
        &self.jwks
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| Error::Key(format!("creating {}: {}", path.display(), e.kind())))?;
    f.write_all(bytes)
        .map_err(|e| Error::Key(format!("writing key: {}", e.kind())))
}
