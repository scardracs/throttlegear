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

- [ThrottleGear.py](ThrottleGear.py): The standalone Python script.
- [DETAILS.md](Documentation/DETAILS.md): Detailed explanation of the cryptography internals and parameter derivation.
- [CONTRIBUTING.md](CONTRIBUTING.md): Contribution guidelines.
- [LICENSE](LICENSE): The MIT License for the Python script.

*(Note: No proprietary XML configuration files are hosted in this repository. You must copy your own configuration file from your system).*

---

## How to Proceed

To run the script, specify the input file (`-i` / `--input`) and the output file (`-o` / `--output`):

### Decrypting an Encrypted XML file:
```bash
python ThrottleGear.py -i ThrottleGear_YOURMODEL.xml -o ThrottleGear_YOURMODEL_decrypted.xml
```

### Encrypting a Plain-Text XML file:
```bash
python ThrottleGear.py -i ThrottleGear_YOURMODEL_decrypted.xml -o ThrottleGear_YOURMODEL_encrypted.xml
```

Upon successful completion, the script will output:
```
Success! Processed file saved to: /absolute/path/to/output.xml
```

### Generating Linux Kernel `asus-armoury` Power Limits Struct:
If you are using this tool to compile a quirk entry for the Linux kernel `asus-armoury` driver, you can use the `-c` / `--c-struct` argument. This automatically decrypts the XML in-memory if needed, extracts the power/thermal limits, and formats them as a C struct initialization block:

```bash
python ThrottleGear.py -i ThrottleGear_YOURMODEL.xml -c
```

**Additional Options for C Struct & Patch Generation:**
*   `-p <profile>` / `--profile <profile>` (or `--device`): Specifies the platform/device profile tag under the root to extract settings from (e.g. `Ryzen` or `Eng`). If not specified and multiple exist, the script lists available profiles, emits a warning, and defaults to the first one.
*   `-g <watts>` / `--gpu-base-tgp <watts>`: Specifies the baseline GPU TGP in Watts (default is `55`). This base value is added to the XML's GPU TGP offsets to produce absolute limits (e.g., `65W` base + `50W` offset = `115W` max).
*   `-n` / `--no-fan-curve`: Sets `.requires_fan_curve = false` in the generated struct (defaults to `true`).
*   `-P` / `--generate-patch`: Generates a fully formatted Git patch for the Linux kernel `asus-armoury` driver. It reads the driver's header, inserts the new entry alphabetically into the `power_limits[]` table, generates a unified diff, and saves it under the `patches/` directory. **Note: `-U/--username` and `-E/--email` are mandatory when this option is set.**
*   `-k <path>` / `--kernel-dir <path>`: Path to a local Linux kernel source tree. If specified, the tool reads and patches the local `drivers/platform/x86/asus-armoury.h` file. If omitted, the header is dynamically fetched from the Torvalds mainline repository on GitHub.
*   `-d <path>` / `--patch-dir <path>`: Directory where the generated Git patch file will be saved (defaults to `patches/` in the workspace).
*   `-U <name>` / `--username <name>`: Username of the patch author/signer (e.g. `'Jane Doe'`). **Mandatory when generating a patch.**
*   `-E <email>` / `--email <email>` / `--mail <email>`: Email of the patch author/signer (e.g. `'jane@example.com'`). **Mandatory when generating a patch.**

---

## Running Unit Tests

This project includes a comprehensive unit test suite written using Python's standard `unittest` library. You can run all tests with:

```bash
python -m unittest discover -s tests
```

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
