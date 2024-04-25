use crate::{get_content, process_genpass, TextSignFormat};
use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::{collections::HashMap, io::Read};

use base64::{engine::general_purpose::STANDARD, Engine as _};

use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    consts::{U12, U32},
    ChaCha20Poly1305,
};

pub trait TextSigner {
    // signer could sign any input data
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextVerifier {
    // verifier could verify any input data
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool>;
}

pub struct Blake3 {
    key: [u8; 32],
}

pub struct Ed25519Signer {
    key: SigningKey,
}

pub struct Ed25519Verifier {
    key: VerifyingKey,
}

impl TextSigner for Blake3 {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let ret = blake3::keyed_hash(&self.key, &buf);
        Ok(ret.as_bytes().to_vec())
    }
}

impl TextVerifier for Blake3 {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let ret = blake3::keyed_hash(&self.key, &buf);
        Ok(ret.as_bytes() == sig)
    }
}

impl TextSigner for Ed25519Signer {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let signature = self.key.sign(&buf);
        Ok(signature.to_bytes().to_vec())
    }
}

impl TextVerifier for Ed25519Verifier {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let sig = (&sig[..64]).try_into()?;
        let signature = Signature::from_bytes(sig);
        Ok(self.key.verify(&buf, &signature).is_ok())
    }
}

impl Blake3 {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        // convert &[u8] to &[u8; 32]
        let key = (&key[..32]).try_into()?;
        Ok(Self::new(key))
    }

    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let key = process_genpass(32, true, true, true, true)?;
        let mut map = HashMap::new();
        map.insert("blake3.txt", key.as_bytes().to_vec());
        Ok(map)
    }
}

impl Ed25519Signer {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = (&key[..32]).try_into()?;
        Ok(Self::new(key))
    }

    pub fn new(key: &[u8; 32]) -> Self {
        let key = SigningKey::from_bytes(key);
        Self { key }
    }

    fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let mut csprng = OsRng;
        let sk: SigningKey = SigningKey::generate(&mut csprng);
        let pk: VerifyingKey = (&sk).into();
        let mut map = HashMap::new();
        map.insert("ed25519.sk", sk.to_bytes().to_vec());
        map.insert("ed25519.pk", pk.to_bytes().to_vec());

        Ok(map)
    }
}

impl Ed25519Verifier {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = (&key[..32]).try_into()?;
        let key = VerifyingKey::from_bytes(key)?;
        Ok(Self { key })
    }
}

pub fn process_text_sign(
    reader: &mut dyn Read,
    key: &[u8], // (ptr, length)
    format: TextSignFormat,
) -> Result<Vec<u8>> {
    let signer: Box<dyn TextSigner> = match format {
        TextSignFormat::Blake3 => Box::new(Blake3::try_new(key)?),
        TextSignFormat::Ed25519 => Box::new(Ed25519Signer::try_new(key)?),
    };

    signer.sign(reader)
}

pub fn process_text_verify(
    reader: &mut dyn Read,
    key: &[u8],
    sig: &[u8],
    format: TextSignFormat,
) -> Result<bool> {
    let verifier: Box<dyn TextVerifier> = match format {
        TextSignFormat::Blake3 => Box::new(Blake3::try_new(key)?),
        TextSignFormat::Ed25519 => Box::new(Ed25519Verifier::try_new(key)?),
    };
    verifier.verify(reader, sig)
}

pub fn process_text_key_generate(format: TextSignFormat) -> Result<HashMap<&'static str, Vec<u8>>> {
    match format {
        TextSignFormat::Blake3 => Blake3::generate(),
        TextSignFormat::Ed25519 => Ed25519Signer::generate(),
    }
}

pub fn process_text_encrypt(input_key: String) -> Result<String> {
    let key_file = "fixtures/chacha_key.txt";
    let key_string = String::from_utf8(get_content(key_file)?)?;
    //println!("key:{}", key_string);
    let nonce_file = "fixtures/chacha_nonce.txt";
    let nonce_string = String::from_utf8(get_content(nonce_file)?)?;
    //println!("nonce:{}", nonce_string);
    let key_u8: Vec<u8> = STANDARD.decode(key_string)?;
    let nonce_u8 = STANDARD.decode(nonce_string)?;
    let key = GenericArray::<u8, U32>::from_slice(&key_u8);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = GenericArray::<u8, U12>::from_slice(&nonce_u8);

    //println!("key:{}", input_key);
    let ciphertext = cipher.encrypt(nonce, input_key.as_ref()).unwrap();
    let result = STANDARD.encode(ciphertext);
    //println!("result:{}", result);
    Ok(result)
}

pub fn process_text_decrypt(input_key: String) -> Result<String> {
    let key_file = "fixtures/chacha_key.txt";
    let key_string = String::from_utf8(get_content(key_file)?)?;
    //println!("key:{}", key_string);
    let nonce_file = "fixtures/chacha_nonce.txt";
    let nonce_string = String::from_utf8(get_content(nonce_file)?)?;
    //println!("nonce:{}", nonce_string);
    let key_u8: Vec<u8> = STANDARD.decode(key_string)?;
    let nonce_u8 = STANDARD.decode(nonce_string)?;
    let key = GenericArray::<u8, U32>::from_slice(&key_u8);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = GenericArray::<u8, U12>::from_slice(&nonce_u8);
    //println!("key:{}", input_key);
    let key_for_decrypt = STANDARD.decode(input_key)?;
    let ciphertext = cipher.decrypt(nonce, key_for_decrypt.as_ref()).unwrap();
    let result = String::from_utf8(ciphertext)?;
    //println!("result:{}", result);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::result;

    use super::*;
    use anyhow::Ok;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use chacha20poly1305::{
        aead::generic_array::GenericArray,
        consts::{U12, U32},
    };
    use serde_json::from_slice;

    const KEY: &[u8] = include_bytes!("../../fixtures/blake3.txt");

    #[test]
    fn test_process_text_sign() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let mut reader1 = "hello".as_bytes();
        let format = TextSignFormat::Blake3;
        let sig = process_text_sign(&mut reader, KEY, format)?;
        let ret = process_text_verify(&mut reader1, KEY, &sig, format)?;
        assert!(ret);
        Ok(())
    }

    #[test]
    fn testc_process_text_verify() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let format = TextSignFormat::Blake3;
        let sig = "33Ypo4rveYpWmJKAiGnnse-wHQhMVujjmcVkV4Tl43k";
        let sig = URL_SAFE_NO_PAD.decode(sig)?;
        let ret = process_text_verify(&mut reader, KEY, &sig, format)?;
        assert!(ret);
        Ok(())
    }

    #[test]
    fn test_process_text_encrypt() -> Result<()> {
        let msg: String = process_text_encrypt("彭海波".to_string())?;
        println!("{}", msg);
        Ok(())
    }

    #[test]
    fn test_process_text_decrypt() -> Result<()> {
        let msg: String = process_text_decrypt("WkNn4L1o6trrM3JayFm7jCi8jJ+bySSryw==".to_string())?;
        println!("{}", msg);
        Ok(())
    }

    #[test]
    fn test_process_encrypt() -> Result<()> {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let key_base64 = STANDARD.encode(&key.as_slice().to_vec());
        eprintln!("key:{}", key_base64);
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
        let nonce_base64 = STANDARD.encode(&nonce.as_slice().to_vec());
        eprintln!("nonce:{}", nonce_base64);
        let ciphertext = cipher
            .encrypt(&nonce, b"plaintext message".as_ref())
            .unwrap();
        let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
        assert_eq!(&plaintext, b"plaintext message");
        Ok(())
    }

    use crate::{get_content, get_reader};
    #[test]
    fn test_process_encrypt_fix() -> Result<()> {
        let input_key = "fixtures/chacha_key.txt";
        let key_string = String::from_utf8(get_content(input_key)?)?;
        println!("key:{}", key_string);
        let input_nonce = "fixtures/chacha_nonce.txt";
        let nonce_string = String::from_utf8(get_content(input_nonce)?)?;
        println!("nonce:{}", nonce_string);
        let key_u8: Vec<u8> = STANDARD.decode(key_string)?;
        let nonce_u8 = STANDARD.decode(nonce_string)?;
        let key = GenericArray::<u8, U32>::from_slice(&key_u8);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = GenericArray::<u8, U12>::from_slice(&nonce_u8);

        let ciphertext = cipher
            .encrypt(nonce, b"plaintext message".as_ref())
            .unwrap();
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        assert_eq!(&plaintext, b"plaintext message");

        Ok(())
    }
}
