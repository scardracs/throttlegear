use std::ffi::c_void;

// FFI Bindings to OpenSSL libcrypto EVP interface
type EvpCipherCtx = c_void;
type EvpCipher = c_void;
type Engine = c_void;

#[link(name = "crypto")]
unsafe extern "C" {
    fn EVP_CIPHER_CTX_new() -> *mut EvpCipherCtx;
    fn EVP_CIPHER_CTX_free(ctx: *mut EvpCipherCtx);
    fn EVP_aes_256_cbc() -> *const EvpCipher;
    fn EVP_DecryptInit_ex(
        ctx: *mut EvpCipherCtx,
        type_: *const EvpCipher,
        impl_: *mut Engine,
        key: *const u8,
        iv: *const u8,
    ) -> i32;
    fn EVP_DecryptUpdate(
        ctx: *mut EvpCipherCtx,
        out: *mut u8,
        outl: *mut i32,
        in_: *const u8,
        inl: i32,
    ) -> i32;
    fn EVP_DecryptFinal_ex(
        ctx: *mut EvpCipherCtx,
        outm: *mut u8,
        outl: *mut i32,
    ) -> i32;
    fn EVP_EncryptInit_ex(
        ctx: *mut EvpCipherCtx,
        type_: *const EvpCipher,
        impl_: *mut Engine,
        key: *const u8,
        iv: *const u8,
    ) -> i32;
    fn EVP_EncryptUpdate(
        ctx: *mut EvpCipherCtx,
        out: *mut u8,
        outl: *mut i32,
        in_: *const u8,
        inl: i32,
    ) -> i32;
    fn EVP_EncryptFinal_ex(
        ctx: *mut EvpCipherCtx,
        outm: *mut u8,
        outl: *mut i32,
    ) -> i32;
}

/// Derives the AES key and IV from XML attributes.
pub fn get_key_and_iv(model_name: &str, version_str: &str, type_str: &str) -> (Vec<u8>, Vec<u8>) {
    // 32-byte Key derivation
    let mut key = vec![0u8; 32];
    key[0] = if type_str == "DT" { 1 } else { 0 };
    let model_bytes = model_name.as_bytes();
    let copy_len = std::cmp::min(model_bytes.len(), 31);
    key[1..1 + copy_len].copy_from_slice(&model_bytes[..copy_len]);

    // 16-byte IV derivation
    let parts: Vec<&str> = version_str.split('.').collect();
    let major = parts.get(0).and_then(|s| s.parse::<i32>().ok()).unwrap_or(-1);
    let minor = parts.get(1).and_then(|s| s.parse::<i32>().ok()).unwrap_or(0);
    let build = parts.get(2).and_then(|s| s.parse::<i32>().ok()).unwrap_or(-1);
    let revision = parts.get(3).and_then(|s| s.parse::<i32>().ok()).unwrap_or(-1);

    let mut iv = Vec::with_capacity(16);
    iv.extend_from_slice(&major.to_le_bytes());
    iv.extend_from_slice(&minor.to_le_bytes());
    iv.extend_from_slice(&build.to_le_bytes());
    iv.extend_from_slice(&revision.to_le_bytes());

    (key, iv)
}

/// Decrypts ciphertext using AES-256-CBC via OpenSSL libcrypto
pub fn decrypt_aes_256_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let ctx = EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            return Err("EVP_CIPHER_CTX_new failed".to_string());
        }

        let cipher = EVP_aes_256_cbc();
        if EVP_DecryptInit_ex(ctx, cipher, std::ptr::null_mut(), key.as_ptr(), iv.as_ptr()) != 1 {
            EVP_CIPHER_CTX_free(ctx);
            return Err("EVP_DecryptInit_ex failed".to_string());
        }

        // Ciphertext size + block size for PKCS7 padding margin
        let mut out_buf = vec![0u8; ciphertext.len() + 32];
        let mut out_len = 0;

        if EVP_DecryptUpdate(
            ctx,
            out_buf.as_mut_ptr(),
            &mut out_len,
            ciphertext.as_ptr(),
            ciphertext.len() as i32,
        ) != 1 {
            EVP_CIPHER_CTX_free(ctx);
            return Err("EVP_DecryptUpdate failed".to_string());
        }

        let mut final_len = 0;
        let final_ptr = out_buf.as_mut_ptr().add(out_len as usize);

        if EVP_DecryptFinal_ex(ctx, final_ptr, &mut final_len) != 1 {
            EVP_CIPHER_CTX_free(ctx);
            return Err("EVP_DecryptFinal_ex failed (probably bad padding or key)".to_string());
        }

        EVP_CIPHER_CTX_free(ctx);
        out_buf.truncate((out_len + final_len) as usize);
        Ok(out_buf)
    }
}

/// Encrypts plaintext using AES-256-CBC via OpenSSL libcrypto
pub fn encrypt_aes_256_cbc(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let ctx = EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            return Err("EVP_CIPHER_CTX_new failed".to_string());
        }

        let cipher = EVP_aes_256_cbc();
        if EVP_EncryptInit_ex(ctx, cipher, std::ptr::null_mut(), key.as_ptr(), iv.as_ptr()) != 1 {
            EVP_CIPHER_CTX_free(ctx);
            return Err("EVP_EncryptInit_ex failed".to_string());
        }

        let mut out_buf = vec![0u8; plaintext.len() + 32];
        let mut out_len = 0;

        if EVP_EncryptUpdate(
            ctx,
            out_buf.as_mut_ptr(),
            &mut out_len,
            plaintext.as_ptr(),
            plaintext.len() as i32,
        ) != 1 {
            EVP_CIPHER_CTX_free(ctx);
            return Err("EVP_EncryptUpdate failed".to_string());
        }

        let mut final_len = 0;
        let final_ptr = out_buf.as_mut_ptr().add(out_len as usize);

        if EVP_EncryptFinal_ex(ctx, final_ptr, &mut final_len) != 1 {
            EVP_CIPHER_CTX_free(ctx);
            return Err("EVP_EncryptFinal_ex failed".to_string());
        }

        EVP_CIPHER_CTX_free(ctx);
        out_buf.truncate((out_len + final_len) as usize);
        Ok(out_buf)
    }
}

/// Base64 Encoder implementation
pub fn base64_encode(input: &[u8]) -> String {
    const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity((input.len() + 2) / 3 * 4);
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as usize;
        let b1 = if i + 1 < input.len() { input[i + 1] as usize } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] as usize } else { 0 };

        let c0 = b0 >> 2;
        let c1 = ((b0 & 3) << 4) | (b1 >> 4);
        let c2 = ((b1 & 15) << 2) | (b2 >> 6);
        let c3 = b2 & 63;

        result.push(CHARSET[c0] as char);
        result.push(CHARSET[c1] as char);
        if i + 1 < input.len() {
            result.push(CHARSET[c2] as char);
        } else {
            result.push('=');
        }
        if i + 2 < input.len() {
            result.push(CHARSET[c3] as char);
        } else {
            result.push('=');
        }
        i += 3;
    }
    result
}

/// Base64 Decoder implementation
pub fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut lookup = [0u8; 256];
    const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (i, &c) in CHARSET.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }

    let clean_input: String = input.chars().filter(|c| !c.is_whitespace() && *c != '\r' && *c != '\n').collect();
    if clean_input.is_empty() {
        return Ok(Vec::new());
    }
    if clean_input.len() % 4 != 0 {
        return Err("Invalid base64 length".to_string());
    }

    let bytes = clean_input.as_bytes();
    let mut result = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0;
    while i < bytes.len() {
        let c0 = lookup[bytes[i] as usize] as usize;
        let c1 = lookup[bytes[i + 1] as usize] as usize;
        let has_c2 = bytes[i + 2] != b'=';
        let has_c3 = bytes[i + 3] != b'=';

        let c2 = if has_c2 { lookup[bytes[i + 2] as usize] as usize } else { 0 };
        let c3 = if has_c3 { lookup[bytes[i + 3] as usize] as usize } else { 0 };

        let b0 = (c0 << 2) | (c1 >> 4);
        let b1 = ((c1 & 15) << 4) | (c2 >> 2);
        let b2 = ((c2 & 3) << 6) | c3;

        result.push(b0 as u8);
        if has_c2 {
            result.push(b1 as u8);
        }
        if has_c3 {
            result.push(b2 as u8);
        }
        i += 4;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_key_and_iv() {
        let (key, iv) = get_key_and_iv("G614PR", "1.0.5", "NB");
        assert_eq!(key.len(), 32);
        assert_eq!(iv.len(), 16);
        assert_eq!(key[0], 0);
        assert_eq!(&key[1..7], b"G614PR");

        let (key_dt, _) = get_key_and_iv("ModelDT", "1.0.5", "DT");
        assert_eq!(key_dt[0], 1);
    }

    #[test]
    fn test_aes_encrypt_decrypt_roundtrip() {
        let plaintext = b"This is a test plaintext message for AES 256 CBC!";
        let key = vec![1u8; 32];
        let iv = vec![2u8; 16];

        let ciphertext = encrypt_aes_256_cbc(plaintext, &key, &iv).unwrap();
        assert_ne!(ciphertext, plaintext);

        let decrypted = decrypt_aes_256_cbc(&ciphertext, &key, &iv).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_base64() {
        let original = b"Hello, World!";
        let encoded = base64_encode(original);
        assert_eq!(encoded, "SGVsbG8sIFdvcmxkIQ==");

        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }
}
