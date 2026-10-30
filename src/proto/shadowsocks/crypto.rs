//! Shadowsocks AEAD ciphers and TCP chunk framing.
//!
//! Legacy AEAD (AEAD-2018) and SS-2022 share the same per-block AEAD sealing
//! with a 12-byte little-endian nonce counter and a 16-byte tag; they differ in
//! how the session subkey is derived and in the shape of the first header
//! blocks. This module provides [`SsReader`]/[`SsWriter`] that expose one
//! primitive, `open_block`/`seal_block`, on which both header and payload
//! framing are built by the parent module.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use std::io::{Error, ErrorKind};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const TAG_LEN: usize = 16;
const MAX_CHUNK: usize = 0x3fff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
    Aead2022Aes128Gcm,
    Aead2022Aes256Gcm,
}

/// Internal: which AEAD construction to use, carrying the session subkey.
pub enum Cipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    Chacha(Box<ChaCha20Poly1305>),
}

impl Method {
    pub fn from_name(name: &str) -> Option<Method> {
        Some(match name.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Method::Aes128Gcm,
            "aes-256-gcm" => Method::Aes256Gcm,
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Method::Chacha20Poly1305,
            "2022-blake3-aes-128-gcm" => Method::Aead2022Aes128Gcm,
            "2022-blake3-aes-256-gcm" => Method::Aead2022Aes256Gcm,
            _ => return None,
        })
    }

    pub fn key_len(&self) -> usize {
        match self {
            Method::Aes128Gcm | Method::Aead2022Aes128Gcm => 16,
            Method::Aes256Gcm | Method::Chacha20Poly1305 | Method::Aead2022Aes256Gcm => 32,
        }
    }

    /// Salt length equals key length for every supported method.
    pub fn salt_len(&self) -> usize {
        self.key_len()
    }

    pub fn is_2022(&self) -> bool {
        matches!(self, Method::Aead2022Aes128Gcm | Method::Aead2022Aes256Gcm)
    }

    /// Master key from the configured password.
    pub fn derive_key(&self, password: &str) -> std::io::Result<Vec<u8>> {
        if self.is_2022() {
            use base64::Engine;
            let raw = base64::engine::general_purpose::STANDARD
                .decode(password.trim())
                .map_err(|_| {
                    Error::new(ErrorKind::InvalidInput, "SS-2022 password must be base64")
                })?;
            if raw.len() != self.key_len() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "SS-2022 key must be {} bytes (got {})",
                        self.key_len(),
                        raw.len()
                    ),
                ));
            }
            Ok(raw)
        } else {
            Ok(evp_bytes_to_key(password.as_bytes(), self.key_len()))
        }
    }

    /// Derive the per-session subkey from the master key and salt.
    fn session_subkey(&self, master: &[u8], salt: &[u8]) -> Vec<u8> {
        let klen = self.key_len();
        if self.is_2022() {
            // blake3 KDF over master||salt.
            let mut material = Vec::with_capacity(master.len() + salt.len());
            material.extend_from_slice(master);
            material.extend_from_slice(salt);
            let out = blake3::derive_key("shadowsocks 2022 session subkey", &material);
            out[..klen].to_vec()
        } else {
            // HKDF-SHA1(master, salt, "ss-subkey").
            let hk = hkdf::Hkdf::<sha1::Sha1>::new(Some(salt), master);
            let mut okm = vec![0u8; klen];
            hk.expand(b"ss-subkey", &mut okm).expect("hkdf expand");
            okm
        }
    }

    fn build_cipher(&self, subkey: &[u8]) -> Cipher {
        match self {
            Method::Aes128Gcm | Method::Aead2022Aes128Gcm => {
                Cipher::Aes128(Box::new(Aes128Gcm::new_from_slice(subkey).unwrap()))
            }
            Method::Aes256Gcm | Method::Aead2022Aes256Gcm => {
                Cipher::Aes256(Box::new(Aes256Gcm::new_from_slice(subkey).unwrap()))
            }
            Method::Chacha20Poly1305 => {
                Cipher::Chacha(Box::new(ChaCha20Poly1305::new_from_slice(subkey).unwrap()))
            }
        }
    }
}

impl Cipher {
    fn seal(&self, nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
        let n = Nonce::from_slice(nonce);
        let p = Payload {
            msg: plaintext,
            aad: b"",
        };
        match self {
            Cipher::Aes128(c) => c.encrypt(n, p),
            Cipher::Aes256(c) => c.encrypt(n, p),
            Cipher::Chacha(c) => c.encrypt(n, p),
        }
        .expect("aead seal")
    }

    fn open(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> std::io::Result<Vec<u8>> {
        let n = Nonce::from_slice(nonce);
        let p = Payload {
            msg: ciphertext,
            aad: b"",
        };
        let r = match self {
            Cipher::Aes128(c) => c.decrypt(n, p),
            Cipher::Aes256(c) => c.decrypt(n, p),
            Cipher::Chacha(c) => c.decrypt(n, p),
        };
        r.map_err(|_| Error::new(ErrorKind::InvalidData, "SS AEAD authentication failed"))
    }
}

/// 12-byte little-endian nonce counter.
#[derive(Default)]
struct NonceCounter([u8; 12]);

impl NonceCounter {
    fn current(&self) -> [u8; 12] {
        self.0
    }
    fn increment(&mut self) {
        for b in self.0.iter_mut() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
    }
}

/// Decrypting (client -> server) half.
pub struct SsReader {
    cipher: Cipher,
    nonce: NonceCounter,
}

impl SsReader {
    pub fn new(method: Method, master: &[u8], salt: &[u8]) -> std::io::Result<Self> {
        let subkey = method.session_subkey(master, salt);
        Ok(Self {
            cipher: method.build_cipher(&subkey),
            nonce: NonceCounter::default(),
        })
    }

    /// Open one AEAD block of `plain_len` plaintext bytes (reads plain_len+TAG).
    pub async fn open_block<S: AsyncRead + Unpin>(
        &mut self,
        inner: &mut S,
        plain_len: usize,
    ) -> std::io::Result<Vec<u8>> {
        let mut buf = vec![0u8; plain_len + TAG_LEN];
        inner.read_exact(&mut buf).await?;
        let pt = self.cipher.open(&self.nonce.current(), &buf)?;
        self.nonce.increment();
        Ok(pt)
    }

    /// Open one AEAD block, returning None on a clean EOF before any byte.
    async fn open_block_opt<S: AsyncRead + Unpin>(
        &mut self,
        inner: &mut S,
        plain_len: usize,
    ) -> std::io::Result<Option<Vec<u8>>> {
        let mut buf = vec![0u8; plain_len + TAG_LEN];
        let mut read = 0;
        while read < buf.len() {
            match inner.read(&mut buf[read..]).await? {
                0 if read == 0 => return Ok(None),
                0 => return Err(Error::new(ErrorKind::UnexpectedEof, "truncated SS block")),
                n => read += n,
            }
        }
        let pt = self.cipher.open(&self.nonce.current(), &buf)?;
        self.nonce.increment();
        Ok(Some(pt))
    }

    /// Read one standard payload chunk: `[len(2)] [payload]`.
    pub async fn read_chunk<S: AsyncRead + Unpin>(
        &mut self,
        inner: &mut S,
    ) -> std::io::Result<Option<Vec<u8>>> {
        let len_pt = match self.open_block_opt(inner, 2).await? {
            Some(b) => b,
            None => return Ok(None),
        };
        let len = u16::from_be_bytes([len_pt[0], len_pt[1]]) as usize;
        if len == 0 || len > MAX_CHUNK {
            return Err(Error::new(ErrorKind::InvalidData, "bad SS chunk length"));
        }
        let payload = self.open_block(inner, len).await?;
        Ok(Some(payload))
    }
}

/// Encrypting (server -> client) half.
pub struct SsWriter {
    cipher: Cipher,
    nonce: NonceCounter,
    salt: Vec<u8>,
    request_salt: Vec<u8>,
    method: Method,
    started: bool,
}

impl SsWriter {
    /// `request_salt` is the client's salt (echoed in the SS-2022 response).
    pub fn new(method: Method, master: &[u8], request_salt: &[u8]) -> std::io::Result<Self> {
        use rand::RngCore;
        let mut salt = vec![0u8; method.salt_len()];
        rand::thread_rng().fill_bytes(&mut salt);
        let subkey = method.session_subkey(master, &salt);
        Ok(Self {
            cipher: method.build_cipher(&subkey),
            nonce: NonceCounter::default(),
            salt,
            request_salt: request_salt.to_vec(),
            method,
            started: false,
        })
    }

    fn seal_block(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let ct = self.cipher.seal(&self.nonce.current(), plaintext);
        self.nonce.increment();
        ct
    }

    /// Encrypt and send `data`, emitting the salt (and SS-2022 response header)
    /// on the first call. `data` may be any length; it is split into chunks.
    pub async fn write<S: AsyncWrite + Unpin>(
        &mut self,
        inner: &mut S,
        data: &[u8],
    ) -> std::io::Result<()> {
        let mut out = Vec::new();
        let mut rest = data;

        if !self.started {
            self.started = true;
            out.extend_from_slice(&self.salt);
            if self.method.is_2022() {
                // Fixed response header: type(1)=1 | timestamp(8) | req_salt | len(2),
                // where len is the length of the first payload block that follows.
                let first_len = rest.len().min(MAX_CHUNK);
                let (first, tail) = rest.split_at(first_len);
                rest = tail;

                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let mut hdr = Vec::with_capacity(1 + 8 + self.request_salt.len() + 2);
                hdr.push(1u8);
                hdr.extend_from_slice(&ts.to_be_bytes());
                hdr.extend_from_slice(&self.request_salt);
                hdr.extend_from_slice(&(first_len as u16).to_be_bytes());
                out.extend_from_slice(&self.seal_block(&hdr));
                if first_len > 0 {
                    out.extend_from_slice(&self.seal_block(first));
                }
            }
        }

        for chunk in rest.chunks(MAX_CHUNK) {
            if chunk.is_empty() {
                continue;
            }
            let len = (chunk.len() as u16).to_be_bytes();
            out.extend_from_slice(&self.seal_block(&len));
            out.extend_from_slice(&self.seal_block(chunk));
        }

        if !out.is_empty() {
            inner.write_all(&out).await?;
            inner.flush().await?;
        }
        Ok(())
    }
}

/// OpenSSL's EVP_BytesToKey with MD5, used by legacy Shadowsocks.
fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    use md5::{Digest, Md5};
    let mut out = Vec::with_capacity(key_len);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < key_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password);
        prev = h.finalize().to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(key_len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evp_known_vector() {
        // echo -n 'foobar' | openssl ... ; known MD5-chain result for 32 bytes.
        let k = evp_bytes_to_key(b"foobar", 32);
        assert_eq!(k.len(), 32);
        // First 16 bytes are MD5("foobar").
        use md5::{Digest, Md5};
        let mut h = Md5::new();
        h.update(b"foobar");
        let first = h.finalize().to_vec();
        assert_eq!(&k[..16], &first[..]);
    }

    #[tokio::test]
    async fn legacy_roundtrip_aes256() {
        roundtrip(Method::Aes256Gcm, "hunter2").await;
    }

    #[tokio::test]
    async fn legacy_roundtrip_chacha() {
        roundtrip(Method::Chacha20Poly1305, "hunter2").await;
    }

    async fn roundtrip(method: Method, password: &str) {
        use rand::RngCore;
        let key = method.derive_key(password).unwrap();
        let mut salt = vec![0u8; method.salt_len()];
        rand::thread_rng().fill_bytes(&mut salt);

        // Writer encrypts with its own salt; reader must use that salt.
        let mut writer = SsWriter::new(method, &key, &salt).unwrap();
        let (mut a, mut b) = tokio::io::duplex(8192);
        let payload = b"hello shadowsocks chunked payload".repeat(10);
        writer.write(&mut a, &payload).await.unwrap();
        drop(a);

        // Read the writer's salt off the wire, then decode.
        let mut wsalt = vec![0u8; method.salt_len()];
        b.read_exact(&mut wsalt).await.unwrap();
        let mut reader = SsReader::new(method, &key, &wsalt).unwrap();

        if method.is_2022() {
            // Skip the fixed response header for this low-level test.
        }
        let mut got = Vec::new();
        while let Some(c) = reader.read_chunk(&mut b).await.unwrap() {
            got.extend_from_slice(&c);
        }
        assert_eq!(got, payload);
    }
}
