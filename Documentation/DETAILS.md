# ThrottleGear XML Cryptography Internals

This document explains the cryptography, parameter derivation, and implementation details of the pure Python ASUS ThrottleGear XML encryptor/decryptor.

---

## 1. Parameter Derivation

The encryption uses **AES-256-CBC** with PKCS7 padding. The cryptographic key and Initialization Vector (IV) are derived directly from the root attributes of the `<ThrottlePluginConfig>` XML element:

### A. Key Derivation (32 Bytes / 256 Bits)
The key is determined by the `Type` and `ModelName` attributes:
1. A 32-byte array initialized to `0`.
2. The first byte (index `0`) is set to:
   - `1` if `Type` is `"DT"` (Desktop).
   - `0` otherwise (e.g., `"NB"` for notebooks, `"NUC"`).
3. The ASCII bytes of the `ModelName` attribute are copied into the key array starting at index `1`, up to a maximum of 31 bytes.
4. The remaining bytes of the array are left as `0`.

**C# Equivalent:**
```csharp
byte[] key = new byte[32];
key[0] = (type == "DT") ? (byte)1 : (byte)0;
Array.Copy(Encoding.ASCII.GetBytes(modelName), 0, key, 1, Math.Min(31, modelName.Length));
```

---

### B. IV Derivation (16 Bytes / 128 Bits)
The initial IV is derived from the `Version` attribute (e.g., `"1.0.5"` or `"1.0.5.2"`):
1. The version string is parsed into four integer components: `Major`, `Minor`, `Build`, and `Revision`.
2. Undefined components in the version string (such as `Revision` in `"1.0.5"`) default to `-1`.
3. Each component is converted to a 32-bit signed integer in little-endian format (4 bytes each).
4. The four components are concatenated sequentially:
   - Bytes 0-3: `Major`
   - Bytes 4-7: `Minor`
   - Bytes 8-11: `Build`
   - Bytes 12-15: `Revision`

For `"1.0.5"`, the parsed components are `Major=1`, `Minor=0`, `Build=5`, `Revision=-1`, which results in the following 16-byte array:
`\x01\x00\x00\x00 \x00\x00\x00\x00 \x05\x00\x00\x00 \xff\xff\xff\xff`

**C# Equivalent:**
```csharp
byte[] iv = new byte[16];
Array.Copy(BitConverter.GetBytes(version.Major), 0, iv, 0, 4);
Array.Copy(BitConverter.GetBytes(version.Minor), 0, iv, 4, 4);
Array.Copy(BitConverter.GetBytes(version.Build), 0, iv, 8, 4);
Array.Copy(BitConverter.GetBytes(version.Revision), 0, iv, 12, 4);
```

---

## 2. XML Encryption Standards

The XML files follow the standard **W3C XML Encryption Syntax and Processing** specification:

1. **Outer Encryption (`content: false`)**:
   The entire child element is serialized to a UTF-8 string and encrypted. The resulting base64 string is stored as a replacement element.
2. **IV Prepending**:
   When encrypting in CBC mode, standard XML Encryption prepends the 16-byte initialization vector to the beginning of the ciphertext. 
   - **On Encryption**: The payload stored in `<CipherValue>` is `Base64Encode(IV + Ciphertext)`.
   - **On Decryption**: The first 16 bytes of the decoded binary payload are extracted as the actual decryption IV, and the remaining bytes are decrypted using the derived `Key`.
3. **Encrypted Node Structure**:
   ```xml
   <EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns="http://www.w3.org/2001/04/xmlenc#">
     <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc" />
     <CipherData>
       <CipherValue>{base64_payload}</CipherValue>
     </CipherData>
   </EncryptedData>
   ```

---

## 3. Pure Python Implementation Details

Since the Python standard library does not include a native interface for symmetric AES encryption, the script employs Python's `ctypes` foreign function interface to load the system's pre-installed OpenSSL dynamic library (`libcrypto`).

### A. OpenSSL EVP API Loading
The script looks for standard Linux OpenSSL shared objects in order of preference:
1. `libcrypto.so`
2. `libcrypto.so.3`
3. `libcrypto.so.1.1`

It maps the following low-level C functions:
- `EVP_CIPHER_CTX_new()` / `EVP_CIPHER_CTX_free()`: Allocate and free the cipher context structure.
- `EVP_aes_256_cbc()`: Fetch the cipher type structure for AES-256-CBC.
- `EVP_DecryptInit_ex()` / `EVP_EncryptInit_ex()`: Bind the context, cipher type, key, and IV.
- `EVP_DecryptUpdate()` / `EVP_EncryptUpdate()`: Process block updates.
- `EVP_DecryptFinal_ex()` / `EVP_EncryptFinal_ex()`: Flush the final block and perform PKCS7 padding verification/generation.

### B. Standard XML Parsing
`xml.etree.ElementTree` is used to load, traverse, and modify the XML tree in memory. 
- Elements are indented nicely before writing using `ET.indent()` (available in Python 3.9+).
- Namespaces are registered with `ET.register_namespace` to ensure output elements do not get prefixed with auto-generated namespace abbreviations (e.g., `<ns0:EncryptedData>`).

---

## 4. License

This Python implementation is distributed under the terms of the MIT License. See the accompanying [LICENSE](../LICENSE) file for the full text.
