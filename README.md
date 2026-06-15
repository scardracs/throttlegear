# ThrottleGear XML Encryptor/Decryptor

This repository contains a standalone Python script designed to decrypt and encrypt ASUS ThrottleGear configuration XML files (such as those used by Armoury Crate).

## Advantages of the Pure Python Version
- **Dual-mode support**: Automatically detects if the input file is encrypted or decrypted, and performs the opposite operation.

---

## Prerequisites

To run this tool, you only need:
- **Python 3**
- **OpenSSL (libcrypto)** (pre-installed on almost all Linux distributions)

---

## File Structure

- [ThrottleGearXML.py](ThrottleGearXML.py): The standalone Python script.
- [Documentation/DETAILS.md](Documentation/DETAILS.md): Detailed explanation of the cryptography internals and parameter derivation.
- [LICENSE](LICENSE): The MIT License for the Python script.

*(Note: No proprietary XML configuration files are hosted in this repository. You must copy your own configuration file from your system).*

---

## How to Proceed

To run the script, specify the input file (`-i` / `--input`) and the output file (`-o` / `--output`):

### Decrypting an Encrypted XML file:
```bash
python ThrottleGearXML.py -i ThrottleGear_YOURMODEL.xml -o ThrottleGear_YOURMODEL_decrypted.xml
```

### Encrypting a Plain-Text XML file:
```bash
python ThrottleGearXML.py -i ThrottleGear_YOURMODEL_decrypted.xml -o ThrottleGear_YOURMODEL_encrypted.xml
```

Upon successful completion, the script will output:
```
Success! Processed file saved to: /absolute/path/to/output.xml
```

### Generating Linux Kernel `asus-armoury` Power Limits Struct:
If you are using this tool to compile a quirk entry for the Linux kernel `asus-armoury` driver, you can use the `-c` / `--c-struct` argument. This automatically decrypts the XML in-memory if needed, extracts the power/thermal limits, and formats them as a C struct initialization block:

```bash
python ThrottleGearXML.py -i ThrottleGear_YOURMODEL.xml -c --gpu-base-tgp 65
```

**Additional Options for C Struct Generation:**
*   `--gpu-base-tgp <watts>`: Specifies the baseline GPU TGP in Watts (default is `55`). This base value is added to the XML's GPU TGP offsets to produce absolute limits (e.g., `65W` base + `50W` offset = `115W` max).
*   `--no-fan-curve`: Sets `.requires_fan_curve = false` in the generated struct (defaults to `true`).

---

## Legal Disclaimer

**IMPORTANT: Read this before proceeding.**

- While the Python code itself is open-source (MIT licensed) and contains no proprietary code or copyrights, extracting, decrypting, and modifying XML configuration files is done **entirely at the user's own risk**.
- Modifying system configuration files might cause hardware instability, driver errors, or Armoury Crate malfunctioning.
- The author of this repository is not affiliated, associated, authorized, endorsed by, or in any way officially connected with ASUSTeK Computer Inc. (ASUS).

---

## How It Works Under the Hood

The script reads the XML and looks at the `Cryptography` attribute on the root `<ThrottlePluginConfig>` element:

1. **Parameters Derivation**:
   - **Key**: Derived from the `Type` and `ModelName` attributes. It forms a 32-byte key (AES-256) where the first byte is `1` for `"DT"` and `0` otherwise, followed by the ASCII bytes of the model name.
   - **IV**: Derived from the `Version` attribute (Major, Minor, Build, Revision) packed as 32-bit little-endian integers.
2. **Decryption / Encryption**:
   - **Decryption**: For each `<EncryptedData>` element, the script extracts the base64 payload. The first 16 bytes of the payload represent the IV (prepended per W3C XML Encryption standards), and the remainder is the ciphertext. Decrypted XML is parsed and appended back to the root.
   - **Encryption**: Each child of the root is serialized to UTF-8, encrypted using AES-256-CBC, and wrapped inside a standard `<EncryptedData>` element with the IV prepended.
