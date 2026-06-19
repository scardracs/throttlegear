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

def _init_libcrypto():
    import ctypes.util
    
    lib_names = ["libcrypto.so", "libcrypto.so.3", "libcrypto.so.1.1"]
    found = ctypes.util.find_library("crypto")
    if found:
        lib_names.insert(0, found)
        
    for lib_name in lib_names:
        try:
            lib = ctypes.CDLL(lib_name)
        except OSError:
            continue
            
        lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
        lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
        lib.EVP_aes_256_cbc.restype = ctypes.c_void_p
        
        lib.EVP_DecryptInit_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p
        ]
        lib.EVP_DecryptInit_ex.restype = ctypes.c_int
        
        lib.EVP_DecryptUpdate.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_void_p,
            ctypes.c_int
        ]
        lib.EVP_DecryptUpdate.restype = ctypes.c_int
        
        lib.EVP_DecryptFinal_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int)
        ]
        lib.EVP_DecryptFinal_ex.restype = ctypes.c_int
        
        lib.EVP_EncryptInit_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p
        ]
        lib.EVP_EncryptInit_ex.restype = ctypes.c_int
        
        lib.EVP_EncryptUpdate.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_void_p,
            ctypes.c_int
        ]
        lib.EVP_EncryptUpdate.restype = ctypes.c_int
        
        lib.EVP_EncryptFinal_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int)
        ]
        lib.EVP_EncryptFinal_ex.restype = ctypes.c_int
        
        return lib
    raise RuntimeError("Could not load OpenSSL libcrypto library")

_LIBCRYPTO = _init_libcrypto()

def decrypt_aes_256_cbc(ciphertext, key, iv):
    ctx = _LIBCRYPTO.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("Failed to create EVP_CIPHER_CTX")
        
    try:
        cipher = _LIBCRYPTO.EVP_aes_256_cbc()
        if _LIBCRYPTO.EVP_DecryptInit_ex(ctx, cipher, None, key, iv) != 1:
            raise RuntimeError("EVP_DecryptInit_ex failed")
            
        out_buf = ctypes.create_string_buffer(len(ciphertext) + 32)
        out_len = ctypes.c_int(0)
        
        if _LIBCRYPTO.EVP_DecryptUpdate(ctx, out_buf, ctypes.byref(out_len), ciphertext, len(ciphertext)) != 1:
            raise RuntimeError("EVP_DecryptUpdate failed")
            
        final_len = ctypes.c_int(0)
        out_buf_final = ctypes.byref(out_buf, out_len.value)
        if _LIBCRYPTO.EVP_DecryptFinal_ex(ctx, out_buf_final, ctypes.byref(final_len)) != 1:
            raise RuntimeError("EVP_DecryptFinal_ex failed")
            
        total_len = out_len.value + final_len.value
        return out_buf.raw[:total_len]
    finally:
        _LIBCRYPTO.EVP_CIPHER_CTX_free(ctx)

def encrypt_aes_256_cbc(plaintext, key, iv):
    ctx = _LIBCRYPTO.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("Failed to create EVP_CIPHER_CTX")
        
    try:
        cipher = _LIBCRYPTO.EVP_aes_256_cbc()
        if _LIBCRYPTO.EVP_EncryptInit_ex(ctx, cipher, None, key, iv) != 1:
            raise RuntimeError("EVP_EncryptInit_ex failed")
            
        out_buf = ctypes.create_string_buffer(len(plaintext) + 32)
        out_len = ctypes.c_int(0)
        
        if _LIBCRYPTO.EVP_EncryptUpdate(ctx, out_buf, ctypes.byref(out_len), plaintext, len(plaintext)) != 1:
            raise RuntimeError("EVP_EncryptUpdate failed")
            
        final_len = ctypes.c_int(0)
        out_buf_final = ctypes.byref(out_buf, out_len.value)
        if _LIBCRYPTO.EVP_EncryptFinal_ex(ctx, out_buf_final, ctypes.byref(final_len)) != 1:
            raise RuntimeError("EVP_EncryptFinal_ex failed")
            
        total_len = out_len.value + final_len.value
        return out_buf.raw[:total_len]
    finally:
        _LIBCRYPTO.EVP_CIPHER_CTX_free(ctx)

def decrypt_xml(root, key):
    min_loader_version = root.attrib.get("MinLoaderVersion", "5.7.7.0")
    decrypted_children = []
    
    for elem in list(root):
        tag = elem.tag
        if tag.endswith("EncryptedData"):
            enc_method_elem = elem.find(".//{http://www.w3.org/2001/04/xmlenc#}EncryptionMethod")
            if enc_method_elem is None:
                enc_method_elem = elem.find(".//EncryptionMethod")
                
            if enc_method_elem is not None:
                algo = enc_method_elem.attrib.get("Algorithm")
                if algo != "http://www.w3.org/2001/04/xmlenc#aes256-cbc":
                    sys.stderr.write(f"Error: Unsupported encryption algorithm: {algo}\n")
                    sys.exit(1)
                    
            cipher_val_elem = elem.find(".//{http://www.w3.org/2001/04/xmlenc#}CipherValue")
            if cipher_val_elem is None:
                cipher_val_elem = elem.find(".//CipherValue")
            
            if cipher_val_elem is not None and cipher_val_elem.text:
                cipher_b64 = cipher_val_elem.text.strip()
                full_ciphertext = base64.b64decode(cipher_b64)
                if len(full_ciphertext) < 16:
                    sys.stderr.write("Error: Ciphertext too short to contain IV.\n")
                    sys.exit(1)
                
                # In W3C XML Encryption, the IV is prepended to the ciphertext
                extracted_iv = full_ciphertext[:16]
                actual_ciphertext = full_ciphertext[16:]
                
                decrypted_bytes = decrypt_aes_256_cbc(actual_ciphertext, key, extracted_iv)
                decrypted_str = decrypted_bytes.decode('utf-8')
                
                decrypted_elem = ET.fromstring(decrypted_str)
                decrypted_children.append(decrypted_elem)
                
    root.clear()
    root.attrib["MinLoaderVersion"] = min_loader_version
    root.attrib["Cryptography"] = "Decrypted"
    
    for child in decrypted_children:
        root.append(child)

def encrypt_xml(root, key, iv):
    min_loader_version = root.attrib.get("MinLoaderVersion", "5.7.7.0")
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
    root.attrib["MinLoaderVersion"] = min_loader_version
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
        decrypt_xml(root, key)
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

def validate_limits(ac_limits, dc_limits, gpu_base_tgp):
    warnings = []
    if gpu_base_tgp < 30 or gpu_base_tgp > 200:
        warnings.append(f"GPU base TGP ({gpu_base_tgp}W) is outside the typical notebook range (30W-200W).")
        
    for name, limits in [("AC", ac_limits), ("DC", dc_limits)]:
        for key, val in limits.items():
            if val < 0:
                warnings.append(f"[{name}] {key} has a negative value ({val}).")
            
            # Check temp target bounds
            if "temp_target" in key:
                if val < 0 or val > 100:
                    warnings.append(f"[{name}] Temperature target {key} ({val}°C) is outside realistic range (0°C-100°C).")
            
            # Check TGP bounds
            if "tgp" in key:
                if val < 0 or val > 500:
                    warnings.append(f"[{name}] GPU TGP {key} ({val}W) is outside typical range (0W-500W).")

        # Compare min/max
        for prefix in ["ppt_pl1_spl", "ppt_pl2_sppt", "ppt_pl3_fppt", "ppt_apu_sppt", "ppt_platform_sppt", "nv_temp_target", "nv_dynamic_boost", "nv_tgp"]:
            min_key = f"{prefix}_min"
            max_key = f"{prefix}_max"
            if min_key in limits and max_key in limits:
                if limits[min_key] > limits[max_key]:
                    warnings.append(f"[{name}] Min limit {min_key} ({limits[min_key]}) is greater than max limit {max_key} ({limits[max_key]}).")
                
                # Check default value bounds
                def_key = f"{prefix}_def"
                if def_key in limits:
                    if limits[def_key] < limits[min_key] or limits[def_key] > limits[max_key]:
                        warnings.append(f"[{name}] Default limit {def_key} ({limits[def_key]}) is outside [min, max] range [{limits[min_key]}, {limits[max_key]}].")
                        
    return warnings

def extract_cpu_limits(cpu_settings, dc=False):
    """Extract CPU AC/DC power limits from XML settings."""
    limits = {}
    if cpu_settings is None:
        return limits
    overclock_items = cpu_settings.find("OverclockItems")
    if overclock_items is None:
        return limits
        
    prefix = "DC" if dc else ""
    for tag, field in [
        ("STAPM", "ppt_pl1_spl"),
        ("PPTLimit", "ppt_pl2_sppt"),
        ("fPPTLimit", "ppt_pl3_fppt"),
        ("APUsPPTLimit", "ppt_apu_sppt"),
        ("PlatformsPPT", "ppt_platform_sppt")
    ]:
        elem = overclock_items.find(tag)
        if elem is not None and elem.attrib.get("IsEnabled") == "True":
            try:
                min_val = int(elem.attrib.get(f"{prefix}LowerLimit", 0))
                max_val = int(elem.attrib.get(f"{prefix}UpperLimit", 0))
                def_val = int(elem.attrib.get(f"{prefix}Manual", 0))
            except ValueError:
                continue
            if min_val != 0 or max_val != 0:
                limits[f"{field}_min"] = min_val
                if def_val != max_val and def_val != 0:
                    limits[f"{field}_def"] = def_val
                limits[f"{field}_max"] = max_val
    return limits

def extract_gpu_limits(gpu_settings, gpu_base_tgp=55, dc=False):
    """Extract GPU AC/DC power limits from XML settings."""
    limits = {}
    if gpu_settings is None:
        return limits
    gpu_overclock = gpu_settings.find("NonSLIOverclockItems")
    
    prefix = "DC" if dc else ""
    if gpu_overclock is not None:
        # NBThermalTarget
        elem = gpu_overclock.find("NBThermalTarget")
        if elem is not None and elem.attrib.get("IsEnabled") == "True":
            try:
                min_val = int(elem.attrib.get(f"{prefix}LowerLimit", 0))
                max_val = int(elem.attrib.get(f"{prefix}UpperLimit", 0))
            except ValueError:
                pass
            else:
                if min_val != 0 or max_val != 0:
                    limits["nv_temp_target_min"] = min_val
                    limits["nv_temp_target_max"] = max_val
                    
        # DynamicBoost (AC only)
        if not dc:
            elem = gpu_overclock.find("DynamicBoost")
            if elem is not None and elem.attrib.get("IsEnabled") == "True":
                try:
                    min_val = int(elem.attrib.get("LowerLimit", 0))
                    max_val = int(elem.attrib.get("UpperLimit", 0))
                except ValueError:
                    pass
                else:
                    if min_val != 0 or max_val != 0:
                        limits["nv_dynamic_boost_min"] = min_val
                        limits["nv_dynamic_boost_max"] = max_val
                        
    # TGP (AC only)
    if not dc:
        tgp_items = gpu_settings.find("NonSLITGPItems")
        if tgp_items is not None:
            elem = tgp_items.find("TGPItem")
            if elem is not None and elem.attrib.get("IsEnabled") == "True":
                level_vals = []
                for attr in elem.attrib:
                    if attr.startswith("Level"):
                        try:
                            level_vals.append(int(elem.attrib[attr]))
                        except ValueError:
                            pass
                if level_vals:
                    min_offset = min(level_vals)
                    max_offset = max(level_vals)
                    limits["nv_tgp_min"] = gpu_base_tgp + min_offset
                    limits["nv_tgp_max"] = gpu_base_tgp + max_offset
                    
    return limits

def generate_c_struct(root, profile=None, gpu_base_tgp=55, requires_fan_curve=True):
    model_name = root.attrib.get("ModelName", "UNKNOWN")
    
    # Identify available profiles (children of root containing CPU/GPU settings)
    available_profiles = [
        child.tag for child in root 
        if child.find(".//ThrottlePluginCPUSettings") is not None 
        or child.find(".//ThrottlePluginGPUSettings") is not None
    ]
    
    profile_used = "Default"
    if profile:
        profile_elem = root.find(profile)
        if profile_elem is None:
            profile_elem = root.find(f".//{profile}")
        if profile_elem is None:
            sys.stderr.write(f"Error: Profile '{profile}' not found in XML.\n")
            if available_profiles:
                sys.stderr.write(f"Available profiles: {', '.join(available_profiles)}\n")
            sys.exit(1)
        cpu_settings = profile_elem.find(".//ThrottlePluginCPUSettings")
        gpu_settings = profile_elem.find(".//ThrottlePluginGPUSettings")
        profile_used = profile
    else:
        if len(available_profiles) > 1:
            sys.stderr.write(f"Warning: Multiple profiles found in XML: {', '.join(available_profiles)}. "
                             f"Defaulting to '{available_profiles[0]}'. "
                             f"Use -p/--profile or -d/--device to specify a different one.\n")
            profile_elem = root.find(available_profiles[0])
            cpu_settings = profile_elem.find(".//ThrottlePluginCPUSettings")
            gpu_settings = profile_elem.find(".//ThrottlePluginGPUSettings")
            profile_used = available_profiles[0]
        elif len(available_profiles) == 1:
            profile_elem = root.find(available_profiles[0])
            cpu_settings = profile_elem.find(".//ThrottlePluginCPUSettings")
            gpu_settings = profile_elem.find(".//ThrottlePluginGPUSettings")
            profile_used = available_profiles[0]
        else:
            cpu_settings = root.find(".//ThrottlePluginCPUSettings")
            gpu_settings = root.find(".//ThrottlePluginGPUSettings")
            
    # Extract AC limits
    ac_limits = {}
    ac_limits.update(extract_cpu_limits(cpu_settings, dc=False))
    ac_limits.update(extract_gpu_limits(gpu_settings, gpu_base_tgp=gpu_base_tgp, dc=False))

    # Extract DC limits
    dc_limits = {}
    dc_limits.update(extract_cpu_limits(cpu_settings, dc=True))
    dc_limits.update(extract_gpu_limits(gpu_settings, dc=True))

    # Perform validation checks
    warnings = validate_limits(ac_limits, dc_limits, gpu_base_tgp)
    for warning in warnings:
        sys.stderr.write(f"Warning: {warning}\n")

    # Print C struct
    lines = []
    lines.append("\t{")
    lines.append("\t\t.matches = {")
    lines.append(f'\t\t\tDMI_MATCH(DMI_BOARD_NAME, "{model_name}"),')
    lines.append("\t\t},")
    lines.append("\t\t.driver_data = &(struct power_data) {")
    
    if ac_limits:
        lines.append("\t\t\t.ac_data = &(struct power_limits) {")
        for key, val in ac_limits.items():
            lines.append(f"\t\t\t\t.{key} = {val},")
        lines.append("\t\t\t},")
        
    if dc_limits:
        lines.append("\t\t\t.dc_data = &(struct power_limits) {")
        for key, val in dc_limits.items():
            lines.append(f"\t\t\t\t.{key} = {val},")
        lines.append("\t\t\t},")
        
    fan_curve_str = "true" if requires_fan_curve else "false"
    lines.append(f"\t\t\t.requires_fan_curve = {fan_curve_str},")
    lines.append("\t\t},")
    lines.append("\t},")
    
    return "\n".join(lines), profile_used

def generate_patch_file(model_name, profile_name, c_struct_str, author, sob, kernel_dir=None, patch_dir=None):
    import re
    import urllib.request
    import difflib
    from datetime import datetime
    
    header_content = None
    target_path = None
    
    if kernel_dir:
        target_path = os.path.abspath(os.path.join(kernel_dir, "drivers/platform/x86/asus-armoury.h"))
        if not os.path.exists(target_path):
            sys.stderr.write(f"Error: Local header not found at: {target_path}\n")
            sys.exit(1)
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                header_content = f.read()
        except Exception as e:
            sys.stderr.write(f"Error: Failed to read local header: {e}\n")
            sys.exit(1)
    else:
        url = "https://raw.githubusercontent.com/torvalds/linux/master/drivers/platform/x86/asus-armoury.h"
        print("Fetching mainline asus-armoury.h from GitHub raw...")
        try:
            req = urllib.request.Request(
                url, 
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            with urllib.request.urlopen(req) as response:
                header_content = response.read().decode('utf-8')
        except Exception as e:
            sys.stderr.write(f"Error: Failed to fetch asus-armoury.h from GitHub raw: {e}\n")
            sys.exit(1)
            
    lines = header_content.splitlines()
    
    start_idx = -1
    for i, line in enumerate(lines):
        if "static const struct dmi_system_id power_limits[]" in line:
            start_idx = i
            break
            
    if start_idx == -1:
        sys.stderr.write("Error: Could not find power_limits table in asus-armoury.h\n")
        sys.exit(1)
        
    entries = []
    current_entry_start = -1
    current_board_name = None
    brace_depth = 0
    array_end_idx = -1
    
    for i in range(start_idx + 1, len(lines)):
        line = lines[i]
        
        if "};" in line and brace_depth == 0:
            array_end_idx = i
            break
            
        open_braces = line.count("{")
        close_braces = line.count("}")
        
        if brace_depth == 0 and open_braces > 0:
            current_entry_start = i
            current_board_name = None
            
        brace_depth += open_braces - close_braces
        
        if brace_depth == 0 and current_entry_start != -1:
            entries.append({
                "board_name": current_board_name,
                "start_idx": current_entry_start,
                "end_idx": i
            })
            current_entry_start = -1
            
        if brace_depth > 0:
            match = re.search(r'DMI_MATCH\(DMI_BOARD_NAME,\s*"([^"]+)"\)', line)
            if match:
                current_board_name = match.group(1)
                
    if array_end_idx == -1:
        sys.stderr.write("Error: Could not find end of power_limits table in asus-armoury.h\n")
        sys.exit(1)
        
    def parse_c_struct_limits(c_struct_lines):
        ac_limits = {}
        dc_limits = {}
        fan_curve = None
        current_section = None
        for line in c_struct_lines:
            if ".ac_data" in line:
                current_section = "AC"
            elif ".dc_data" in line:
                current_section = "DC"
            elif "requires_fan_curve" in line:
                match = re.search(r'\.requires_fan_curve\s*=\s*(true|false)', line)
                if match:
                    fan_curve = (match.group(1) == "true")
            else:
                match = re.search(r'\.([a-z0-9_]+)\s*=\s*([0-9]+)', line)
                if match:
                    field = match.group(1)
                    val = int(match.group(2))
                    if current_section == "AC":
                        ac_limits[field] = val
                    elif current_section == "DC":
                        dc_limits[field] = val
        return ac_limits, dc_limits, fan_curve

    c_struct_lines = c_struct_str.splitlines()
    
    # Check if entry already exists
    existing_entry = None
    for entry in entries:
        if entry["board_name"] == model_name:
            existing_entry = entry
            break
            
    if existing_entry:
        print(f"\n[INFO] Quirk for model '{model_name}' already exists in asus-armoury.h.")
        # Parse and compare
        existing_ac, existing_dc, existing_fan = parse_c_struct_limits(lines[existing_entry["start_idx"] : existing_entry["end_idx"] + 1])
        new_ac, new_dc, new_fan = parse_c_struct_limits(c_struct_lines)
        
        differences = []
        all_ac_keys = set(existing_ac.keys()) | set(new_ac.keys())
        for key in sorted(all_ac_keys):
            old_val = existing_ac.get(key)
            new_val = new_ac.get(key)
            if old_val != new_val:
                differences.append(f"AC limit '{key}': mainline has {old_val}, generated has {new_val}")
                
        all_dc_keys = set(existing_dc.keys()) | set(new_dc.keys())
        for key in sorted(all_dc_keys):
            old_val = existing_dc.get(key)
            new_val = new_dc.get(key)
            if old_val != new_val:
                differences.append(f"DC limit '{key}': mainline has {old_val}, generated has {new_val}")
                
        if existing_fan != new_fan:
            differences.append(f"requires_fan_curve: mainline has {existing_fan}, generated has {new_fan}")
            
        if differences:
            print("Differences compared to mainline:")
            for diff in differences:
                print(f"  - {diff}")
        else:
            print("No differences found compared to mainline.")
            
        # Replace the existing entry instead of adding a duplicate
        new_lines = lines[:existing_entry["start_idx"]] + c_struct_lines + lines[existing_entry["end_idx"] + 1:]
    else:
        insert_line_idx = -1
        for entry in entries:
            if entry["board_name"] and entry["board_name"] > model_name:
                insert_line_idx = entry["start_idx"]
                break
        if insert_line_idx == -1:
            insert_line_idx = array_end_idx
        new_lines = lines[:insert_line_idx] + c_struct_lines + lines[insert_line_idx:]
    
    file_rel_path = "drivers/platform/x86/asus-armoury.h"
    diff_generator = difflib.unified_diff(
        lines,
        new_lines,
        fromfile=f"a/{file_rel_path}",
        tofile=f"b/{file_rel_path}",
        lineterm=""
    )
    diff_str = "\n".join(diff_generator)
    
    date_str = datetime.now().astimezone().strftime("%a, %d %b %Y %H:%M:%S %z")
    
    patch_content = f"""From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001
From: {author}
Date: {date_str}
Subject: [PATCH] platform/x86: asus-armoury: Add power limits quirk for {model_name}

Add power limits quirk entry for ASUS ROG {model_name} laptop.
The limits are extracted from the device's ThrottleGear XML configuration
file for the '{profile_name}' profile.

Assisted-by: ThrottleGear
Signed-off-by: {sob}
---
 drivers/platform/x86/asus-armoury.h | {len(c_struct_lines)} +
 1 file changed, {len(c_struct_lines)} insertions(+)

{diff_str}
-- 
2.34.1
"""
    
    if not patch_dir:
        patch_dir = os.path.abspath("patches")
    else:
        patch_dir = os.path.abspath(patch_dir)
        
    model_patch_dir = os.path.join(patch_dir, model_name)
    os.makedirs(model_patch_dir, exist_ok=True)
    
    patch_file_path = os.path.join(
        model_patch_dir, 
        f"0001-platform-x86-asus-armoury-add-power-limits-for-{model_name}.patch"
    )
    
    try:
        with open(patch_file_path, "w", encoding="utf-8") as f:
            f.write(patch_content)
        print(f"Success! Kernel patch saved to: {patch_file_path}")
    except Exception as e:
        sys.stderr.write(f"Error: Failed to write patch file: {e}\n")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="ASUS ThrottleGear XML Encryptor/Decryptor & C Struct Generator (Pure Python)")
    parser.add_argument("-i", "--input", required=True, help="Path to the input XML file")
    parser.add_argument("-o", "--output", help="Path to the output XML file (required unless -c is specified)")
    parser.add_argument("-c", "--c-struct", action="store_true", help="Generate and print the C struct for the Linux kernel driver")
    parser.add_argument("-p", "--profile", "--device", dest="profile", help="Specific profile/device tag to parse from the XML (e.g. Ryzen, Eng)")
    parser.add_argument("-g", "--gpu-base-tgp", type=int, default=55, help="NVIDIA base TGP in Watts (default: 55)")
    parser.add_argument("-n", "--no-fan-curve", action="store_true", help="Set requires_fan_curve to false in the C struct")
    parser.add_argument("-P", "--generate-patch", action="store_true", help="Generate and save a unified diff kernel patch")
    parser.add_argument("-k", "--kernel-dir", help="Path to local Linux kernel directory containing drivers/platform/x86/asus-armoury.h")
    parser.add_argument("-d", "--patch-dir", help="Directory to save the generated patch file (defaults to 'patches')")
    parser.add_argument("-U", "--username", nargs="+", help="Username of the patch author (e.g. 'Jane Doe')")
    parser.add_argument("-E", "--email", "--mail", dest="email", help="Email of the patch author (e.g. 'jane@example.com')")
    args = parser.parse_args()
    
    input_path = os.path.abspath(args.input)
    
    if args.generate_patch:
        if not args.username or not args.email:
            parser.error("-U/--username and -E/--email/--mail are required when -P/--generate-patch is specified.")
            
    if args.c_struct or args.generate_patch:
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
            
        if cryptography == "Encrypted":
            key, iv = get_key_and_iv(model_name, version_str, type_str)
            decrypt_xml(root, key)
            root.attrib["ModelName"] = model_name
            root.attrib["Version"] = version_str
            root.attrib["Type"] = type_str
            
        c_struct_str, profile_used = generate_c_struct(root, profile=args.profile, gpu_base_tgp=args.gpu_base_tgp, requires_fan_curve=not args.no_fan_curve)
        
        if args.generate_patch:
            username_str = " ".join(args.username)
            email_clean = args.email.strip("<>")
            author_identity = f"{username_str} <{email_clean}>"
            generate_patch_file(model_name, profile_used, c_struct_str, author_identity, author_identity, kernel_dir=args.kernel_dir, patch_dir=args.patch_dir)
        else:
            print(c_struct_str)
    else:
        if not args.output:
            parser.error("-o/--output is required unless -c/--c-struct or -P/--generate-patch is specified.")
        output_path = os.path.abspath(args.output)
        process_file(input_path, output_path)

if __name__ == "__main__":
    main()
