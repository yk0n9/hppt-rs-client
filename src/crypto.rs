use aes::{
    Aes128,
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use anyhow::{Result, bail};
use rand::RngCore;
use sha1::{Digest, Sha1};

pub struct JavaAes {
    cipher: Aes128,
}

impl JavaAes {
    pub fn from_java_seed(seed: &str) -> Self {
        Self {
            cipher: Aes128::new_from_slice(&java_sha1prng_aes_key(seed)).expect("AES-128 key"),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let padding = 16 - plaintext.len() % 16;
        let mut output = plaintext.to_vec();
        output.resize(output.len() + padding, padding as u8);
        let (blocks, _) = output.as_chunks_mut::<16>();
        for chunk in blocks {
            let mut block = GenericArray::clone_from_slice(chunk);
            self.cipher.encrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }
        output
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
            bail!("invalid AES/ECB ciphertext length");
        }
        let mut output = ciphertext.to_vec();
        let (blocks, _) = output.as_chunks_mut::<16>();
        for chunk in blocks {
            let mut block = GenericArray::clone_from_slice(chunk);
            self.cipher.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }
        let padding = *output.last().expect("non-empty ciphertext") as usize;
        if padding == 0
            || padding > 16
            || output[output.len() - padding..]
                .iter()
                .any(|byte| *byte as usize != padding)
        {
            bail!("invalid AES/ECB padding");
        }
        output.truncate(output.len() - padding);
        Ok(output)
    }
}

fn java_sha1prng_aes_key(seed: &str) -> [u8; 16] {
    let mut state = Sha1::digest(seed.as_bytes()).to_vec();
    let output = Sha1::digest(&state);

    // This is the state update used by OpenJDK's SHA1PRNG.
    let mut carry = 1_i32;
    let mut changed = false;
    for (state_byte, output_byte) in state.iter_mut().zip(output.iter()) {
        let value = (*state_byte as i8 as i32) + (*output_byte as i8 as i32) + carry;
        let next = value as u8;
        changed |= *state_byte != next;
        *state_byte = next;
        carry = value >> 8;
    }
    if !changed {
        state[0] = state[0].wrapping_add(1);
    }

    output[..16]
        .try_into()
        .expect("SHA-1 output has at least 16 bytes")
}

pub fn grid_encrypt(plaintext: &[u8]) -> Vec<u8> {
    let cipher = JavaAes::from_java_seed("hppt");
    let mut salted = Vec::with_capacity(plaintext.len() * 2);
    let mut rng = rand::thread_rng();
    for byte in plaintext {
        salted.push(*byte);
        salted.push((rng.next_u32() % 255) as u8);
    }
    cipher.encrypt(&salted)
}

pub fn grid_decrypt(ciphertext: &[u8]) -> Result<Vec<u8>> {
    let plaintext = JavaAes::from_java_seed("hppt").decrypt(ciphertext)?;
    if !plaintext.len().is_multiple_of(2) {
        bail!("invalid salted handshake payload length");
    }
    let (pairs, _) = plaintext.as_chunks::<2>();
    Ok(pairs.iter().map(|pair| pair[0]).collect())
}

pub fn session_cipher(password: &str, timestamp_ms: i64) -> JavaAes {
    let bucket = timestamp_ms / (30 * 60 * 1000);
    JavaAes::from_java_seed(&format!("{password}{bucket}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_sha1prng_key_matches_jdk() {
        assert_eq!(
            java_sha1prng_aes_key("password1234"),
            [
                0xd6, 0x57, 0x98, 0xaa, 0xc0, 0xe5, 0xc6, 0xdf, 0x3f, 0x32, 0x0f, 0x8a, 0x30, 0xe0,
                0x26, 0xe7
            ]
        );
    }

    #[test]
    fn aes_uses_java_ecb_pkcs5_padding() {
        let cipher = JavaAes::from_java_seed("password1234");
        let encrypted = cipher.encrypt(b"password");
        assert_eq!(
            encrypted,
            [
                0xe3, 0xf0, 0xbe, 0x0f, 0x0b, 0x3b, 0x04, 0xbf, 0xde, 0x04, 0x1b, 0x85, 0xc6, 0x1f,
                0x0a, 0x4f
            ]
        );
        assert_eq!(cipher.decrypt(&encrypted).unwrap(), b"password");
    }

    #[test]
    fn grid_cipher_discards_interleaved_salt() {
        let ciphertext = grid_encrypt(b"dt 123456789");
        assert_eq!(grid_decrypt(&ciphertext).unwrap(), b"dt 123456789");
    }
}
