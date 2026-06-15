import argparse
import base64
import ctypes
import os
import struct
import sys
import xml.etree.ElementTree as ET

def get_key_and_iv(model_name, version_str, type_str):
    # GetKey logic
    key = bytearray(32)
    key[0] = 1 if type_str == "DT" else 0
    model_bytes = model_name.encode('ascii')
    key[1:1+len(model_bytes)] = model_bytes[:31]
    
    # GetIV logic
    parts = version_str.split('.')
    major = int(parts[0])
    minor = int(parts[1]) if len(parts) > 1 else 0
    build = int(parts[2]) if len(parts) > 2 else -1
    revision = int(parts[3]) if len(parts) > 3 else -1
    iv = struct.pack('<iiii', major, minor, build, revision)
    
    return bytes(key), iv

def _get_libcrypto():
    for lib_name in ["libcrypto.so", "libcrypto.so.3", "libcrypto.so.1.1"]:
        try:
            return ctypes.CDLL(lib_name)
        except OSError:
            continue
    raise RuntimeError("Could not load OpenSSL libcrypto library")

def decrypt_aes_256_cbc(ciphertext, key, iv):
    libcrypto = _get_libcrypto()
            
    libcrypto.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    libcrypto.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    libcrypto.EVP_aes_256_cbc.restype = ctypes.c_void_p
    
    libcrypto.EVP_DecryptInit_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p
    ]
    libcrypto.EVP_DecryptInit_ex.restype = ctypes.c_int
    
    libcrypto.EVP_DecryptUpdate.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_char_p,
        ctypes.c_int
    ]
    libcrypto.EVP_DecryptUpdate.restype = ctypes.c_int
    
    libcrypto.EVP_DecryptFinal_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int)
    ]
    libcrypto.EVP_DecryptFinal_ex.restype = ctypes.c_int

    ctx = libcrypto.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("Failed to create EVP_CIPHER_CTX")
        
    try:
        cipher = libcrypto.EVP_aes_256_cbc()
        if libcrypto.EVP_DecryptInit_ex(ctx, cipher, None, key, iv) != 1:
            raise RuntimeError("EVP_DecryptInit_ex failed")
            
        out_buf = ctypes.create_string_buffer(len(ciphertext) + 32)
        out_len = ctypes.c_int(0)
        
        if libcrypto.EVP_DecryptUpdate(ctx, out_buf, ctypes.byref(out_len), ciphertext, len(ciphertext)) != 1:
            raise RuntimeError("EVP_DecryptUpdate failed")
            
        final_len = ctypes.c_int(0)
        out_buf_final = ctypes.byref(out_buf, out_len.value)
        if libcrypto.EVP_DecryptFinal_ex(ctx, out_buf_final, ctypes.byref(final_len)) != 1:
            raise RuntimeError("EVP_DecryptFinal_ex failed")
            
        total_len = out_len.value + final_len.value
        return out_buf.raw[:total_len]
    finally:
        libcrypto.EVP_CIPHER_CTX_free(ctx)

def encrypt_aes_256_cbc(plaintext, key, iv):
    libcrypto = _get_libcrypto()
            
    libcrypto.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    libcrypto.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    libcrypto.EVP_aes_256_cbc.restype = ctypes.c_void_p
    
    libcrypto.EVP_EncryptInit_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p
    ]
    libcrypto.EVP_EncryptInit_ex.restype = ctypes.c_int
    
    libcrypto.EVP_EncryptUpdate.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_char_p,
        ctypes.c_int
    ]
    libcrypto.EVP_EncryptUpdate.restype = ctypes.c_int
    
    libcrypto.EVP_EncryptFinal_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int)
    ]
    libcrypto.EVP_EncryptFinal_ex.restype = ctypes.c_int

    ctx = libcrypto.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("Failed to create EVP_CIPHER_CTX")
        
    try:
        cipher = libcrypto.EVP_aes_256_cbc()
        if libcrypto.EVP_EncryptInit_ex(ctx, cipher, None, key, iv) != 1:
            raise RuntimeError("EVP_EncryptInit_ex failed")
            
        out_buf = ctypes.create_string_buffer(len(plaintext) + 32)
        out_len = ctypes.c_int(0)
        
        if libcrypto.EVP_EncryptUpdate(ctx, out_buf, ctypes.byref(out_len), plaintext, len(plaintext)) != 1:
            raise RuntimeError("EVP_EncryptUpdate failed")
            
        final_len = ctypes.c_int(0)
        out_buf_final = ctypes.byref(out_buf, out_len.value)
        if libcrypto.EVP_EncryptFinal_ex(ctx, out_buf_final, ctypes.byref(final_len)) != 1:
            raise RuntimeError("EVP_EncryptFinal_ex failed")
            
        total_len = out_len.value + final_len.value
        return out_buf.raw[:total_len]
    finally:
        libcrypto.EVP_CIPHER_CTX_free(ctx)

def decrypt_xml(root, key, iv):
    decrypted_children = []
    
    for elem in list(root):
        tag = elem.tag
        if tag.endswith("EncryptedData"):
            cipher_val_elem = elem.find(".//{http://www.w3.org/2001/04/xmlenc#}CipherValue")
            if cipher_val_elem is None:
                cipher_val_elem = elem.find(".//CipherValue")
            
            if cipher_val_elem is not None and cipher_val_elem.text:
                cipher_b64 = cipher_val_elem.text.strip()
                full_ciphertext = base64.b64decode(cipher_b64)
                
                # In W3C XML Encryption, the IV is prepended to the ciphertext
                extracted_iv = full_ciphertext[:16]
                actual_ciphertext = full_ciphertext[16:]
                
                decrypted_bytes = decrypt_aes_256_cbc(actual_ciphertext, key, extracted_iv)
                decrypted_str = decrypted_bytes.decode('utf-8')
                
                decrypted_elem = ET.fromstring(decrypted_str)
                decrypted_children.append(decrypted_elem)
                
    root.clear()
    root.attrib["MinLoaderVersion"] = "5.7.7.0"
    root.attrib["Cryptography"] = "Decrypted"
    
    for child in decrypted_children:
        root.append(child)

def encrypt_xml(root, key, iv):
    encrypted_children = []
    xmlenc_ns = "http://www.w3.org/2001/04/xmlenc#"
    ET.register_namespace("", xmlenc_ns)
    
    for elem in list(root):
        # Serialize the entire element to UTF-8 bytes
        plaintext = ET.tostring(elem, encoding='utf-8')
        
        # Encrypt the plaintext using key and IV
        ciphertext = encrypt_aes_256_cbc(plaintext, key, iv)
        
        # W3C standard prepends the IV to the ciphertext
        full_payload = iv + ciphertext
        payload_b64 = base64.b64encode(full_payload).decode('ascii')
        
        # Build <EncryptedData> node structure
        encrypted_data_elem = ET.Element(f"{{{xmlenc_ns}}}EncryptedData", {
            "Type": "http://www.w3.org/2001/04/xmlenc#Element"
        })
        ET.SubElement(encrypted_data_elem, f"{{{xmlenc_ns}}}EncryptionMethod", {
            "Algorithm": "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
        })
        cipher_data_elem = ET.SubElement(encrypted_data_elem, f"{{{xmlenc_ns}}}CipherData")
        cipher_value_elem = ET.SubElement(cipher_data_elem, f"{{{xmlenc_ns}}}CipherValue")
        cipher_value_elem.text = payload_b64
        
        encrypted_children.append(encrypted_data_elem)
        
    root.clear()
    root.attrib["MinLoaderVersion"] = "5.7.7.0"
    root.attrib["Cryptography"] = "Encrypted"
    
    for child in encrypted_children:
        root.append(child)

def process_file(input_path, output_path):
    try:
        tree = ET.parse(input_path)
    except Exception as e:
        print(f"Error: Failed to parse input XML file: {e}")
        sys.exit(1)
        
    root = tree.getroot()
    
    model_name = root.attrib.get("ModelName")
    version_str = root.attrib.get("Version")
    type_str = root.attrib.get("Type")
    cryptography = root.attrib.get("Cryptography")
    
    if not all([model_name, version_str, type_str, cryptography]):
        print("Error: XML is missing required root attributes (ModelName, Version, Type, Cryptography).")
        sys.exit(1)
        
    key, iv = get_key_and_iv(model_name, version_str, type_str)
    
    if cryptography == "Encrypted":
        print("Decrypting XML file...")
        decrypt_xml(root, key, iv)
    elif cryptography == "Decrypted":
        print("Encrypting XML file...")
        encrypt_xml(root, key, iv)
    else:
        print(f"Error: Unknown Cryptography status: {cryptography}")
        sys.exit(1)
        
    # Restore model info attributes
    root.attrib["ModelName"] = model_name
    root.attrib["Version"] = version_str
    root.attrib["Type"] = type_str
    
    try:
        ET.indent(tree, space="  ", level=0)
    except AttributeError:
        pass
        
    try:
        tree.write(output_path, encoding="utf-8", xml_declaration=False)
    except Exception as e:
        print(f"Error: Failed to write output XML file: {e}")
        sys.exit(1)
        
    print(f"Success! Processed file saved to: {output_path}")

def main():
    parser = argparse.ArgumentParser(description="ASUS ThrottleGear XML Encryptor/Decryptor (Pure Python)")
    parser.add_argument("-i", "--input", required=True, help="Path to the input XML file")
    parser.add_argument("-o", "--output", required=True, help="Path to the output XML file")
    args = parser.parse_args()
    
    input_path = os.path.abspath(args.input)
    output_path = os.path.abspath(args.output)
    
    process_file(input_path, output_path)

if __name__ == "__main__":
    main()
