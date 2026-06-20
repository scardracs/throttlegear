mod crypto;
mod limits;
mod patch;
mod xml_processor;

use crypto::get_key_and_iv;
use limits::generate_c_struct;
use patch::generate_patch_file;
use xml_processor::{parse_xml_str, serialize_xml, decrypt_xml, encrypt_xml};

fn print_help() {
    println!("ASUS ThrottleGear XML Encryptor/Decryptor & C Struct Generator (Pure Rust)");
    println!("\nUsage:");
    println!("  throttlegear -i <INPUT> [OPTIONS]");
    println!("\nOptions:");
    println!("  -i, --input <FILE>            Path to the input XML file (required)");
    println!("  -o, --output [<FILE>]         Path to the output XML file (optional suffix auto-derived if value omitted)");
    println!("  -c, --c-struct                Generate and print the C struct for the Linux kernel driver");
    println!("  -p, --profile, --device <P>   Specific profile/device tag to parse from XML (e.g. Ryzen, Eng)");
    println!("  -g, --gpu-base-tgp <WATTS>    NVIDIA base TGP in Watts (default: 55)");
    println!("  -n, --no-fan-curve            Set requires_fan_curve to false in the C struct");
    println!("  -P, --generate-patch          Generate and save a unified diff kernel patch");
    println!("  -k, --kernel-dir <DIR>        Path to local Linux kernel directory containing drivers/platform/x86/asus-armoury.h");
    println!("  -d, --patch-dir <DIR>         Directory to save the generated patch file (defaults to 'patches')");
    println!("  -U, --username <NAME>         Username of the patch author (e.g. 'Jane Doe')");
    println!("  -E, --email, --mail <EMAIL>   Email of the patch author (e.g. 'jane@example.com')");
    println!("  -h, --help                    Print help details");
}

fn derive_output_filename(input_path: &str, cryptography: &str) -> String {
    let path = std::path::Path::new(input_path);
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new(""));
    let file_stem = path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let extension = path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("xml");

    let mut stem = file_stem.to_string();
    if stem.ends_with("_decrypted") {
        stem.truncate(stem.len() - "_decrypted".len());
    } else if stem.ends_with("_encrypted") {
        stem.truncate(stem.len() - "_encrypted".len());
    }

    let suffix = if cryptography == "Encrypted" {
        "_decrypted"
    } else {
        "_encrypted"
    };

    let new_filename = format!("{}{}.{}", stem, suffix, extension);
    if parent.as_os_str().is_empty() {
        new_filename
    } else {
        parent.join(new_filename).to_string_lossy().into_owned()
    }
}

fn main() {
    let args_vec: Vec<String> = std::env::args().collect();
    let mut input = None;
    let mut output = None;
    let mut c_struct = false;
    let mut profile = None;
    let mut gpu_base_tgp = 55;
    let mut no_fan_curve = false;
    let mut generate_patch = false;
    let mut kernel_dir = None;
    let mut patch_dir = None;
    let mut username = None;
    let mut email = None;
    let mut output_flag_present = false;

    let mut i = 1;
    while i < args_vec.len() {
        match args_vec[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "-i" | "--input" => {
                if i + 1 < args_vec.len() {
                    input = Some(args_vec[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: Missing value for -i/--input");
                    std::process::exit(1);
                }
            }
            "-o" | "--output" => {
                output_flag_present = true;
                if i + 1 < args_vec.len() && !args_vec[i + 1].starts_with('-') {
                    output = Some(args_vec[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "-c" | "--c-struct" => {
                c_struct = true;
                i += 1;
            }
            "-p" | "--profile" | "--device" => {
                if i + 1 < args_vec.len() {
                    profile = Some(args_vec[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: Missing value for -p/--profile");
                    std::process::exit(1);
                }
            }
            "-g" | "--gpu-base-tgp" => {
                if i + 1 < args_vec.len() {
                    if let Ok(val) = args_vec[i + 1].parse::<i32>() {
                        gpu_base_tgp = val;
                    } else {
                        eprintln!("Error: Invalid value for -g/--gpu-base-tgp (must be an integer)");
                        std::process::exit(1);
                    }
                    i += 2;
                } else {
                    eprintln!("Error: Missing value for -g/--gpu-base-tgp");
                    std::process::exit(1);
                }
            }
            "-n" | "--no-fan-curve" => {
                no_fan_curve = true;
                i += 1;
            }
            "-P" | "--generate-patch" => {
                generate_patch = true;
                i += 1;
            }
            "-k" | "--kernel-dir" => {
                if i + 1 < args_vec.len() {
                    kernel_dir = Some(args_vec[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: Missing value for -k/--kernel-dir");
                    std::process::exit(1);
                }
            }
            "-d" | "--patch-dir" => {
                if i + 1 < args_vec.len() {
                    patch_dir = Some(args_vec[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: Missing value for -d/--patch-dir");
                    std::process::exit(1);
                }
            }
            "-U" | "--username" => {
                let mut name_parts = Vec::new();
                let mut next_idx = i + 1;
                while next_idx < args_vec.len() && !args_vec[next_idx].starts_with('-') {
                    name_parts.push(args_vec[next_idx].clone());
                    next_idx += 1;
                }
                if name_parts.is_empty() {
                    eprintln!("Error: Missing value for -U/--username");
                    std::process::exit(1);
                }
                username = Some(name_parts.join(" "));
                i = next_idx;
            }
            "-E" | "--email" | "--mail" => {
                if i + 1 < args_vec.len() {
                    email = Some(args_vec[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: Missing value for -E/--email");
                    std::process::exit(1);
                }
            }
            other => {
                eprintln!("Error: Unknown argument '{}'", other);
                print_help();
                std::process::exit(1);
            }
        }
    }

    let input_path = match input {
        Some(path) => path,
        None => {
            eprintln!("Error: -i/--input is required.");
            print_help();
            std::process::exit(1);
        }
    };

    if generate_patch && (username.is_none() || email.is_none()) {
        eprintln!("Error: -U/--username and -E/--email are required when -P/--generate-patch is specified.");
        std::process::exit(1);
    }

    let xml_content = match std::fs::read_to_string(&input_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: Failed to read input file '{}': {}", input_path, e);
            std::process::exit(1);
        }
    };

    let mut root = match parse_xml_str(&xml_content) {
        Ok(elem) => elem,
        Err(e) => {
            eprintln!("Error: Failed to parse XML: {}", e);
            std::process::exit(1);
        }
    };

    let model_name = root.get_attribute("ModelName").cloned();
    let version_str = root.get_attribute("Version").cloned();
    let type_str = root.get_attribute("Type").cloned();
    let cryptography = root.get_attribute("Cryptography").cloned();

    let (model_name, version_str, type_str, cryptography) = match (model_name, version_str, type_str, cryptography) {
        (Some(m), Some(v), Some(t), Some(c)) => (m, v, t, c),
        _ => {
            eprintln!("Error: XML is missing required root attributes (ModelName, Version, Type, Cryptography).");
            std::process::exit(1);
        }
    };

    let (key, iv) = get_key_and_iv(&model_name, &version_str, &type_str);

    if c_struct || generate_patch {
        if cryptography == "Encrypted" {
            if let Err(e) = decrypt_xml(&mut root, &key) {
                eprintln!("Error: Failed to decrypt XML: {}", e);
                std::process::exit(1);
            }
            // Restore model info attributes
            root.attributes.insert("ModelName".to_string(), model_name.clone());
            root.attributes.insert("Version".to_string(), version_str.clone());
            root.attributes.insert("Type".to_string(), type_str.clone());
        }

        let (c_struct_str, profile_used) = match generate_c_struct(&root, profile.as_deref(), gpu_base_tgp, !no_fan_curve) {
            Ok(res) => res,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        };

        if generate_patch {
            let author_name = username.unwrap();
            let author_email = email.unwrap();
            let author_identity = format!(
                "{} <{}>",
                author_name,
                author_email.trim_matches(|c| c == '<' || c == '>')
            );
            if let Err(e) = generate_patch_file(
                &model_name,
                &profile_used,
                &c_struct_str,
                &author_identity,
                &author_identity,
                kernel_dir.as_deref(),
                patch_dir.as_deref(),
            ) {
                eprintln!("Error generating patch: {}", e);
                std::process::exit(1);
            }
        } else {
            println!("{}", c_struct_str);
        }
    } else {
        let output_path = if output_flag_present {
            match output {
                Some(path) => path,
                None => {
                    derive_output_filename(&input_path, &cryptography)
                }
            }
        } else {
            eprintln!("Error: -o/--output is required unless -c/--c-struct or -P/--generate-patch is specified.");
            std::process::exit(1);
        };

        if cryptography == "Encrypted" {
            println!("Decrypting XML file...");
            if let Err(e) = decrypt_xml(&mut root, &key) {
                eprintln!("Error decrypting XML: {}", e);
                std::process::exit(1);
            }
        } else if cryptography == "Decrypted" {
            println!("Encrypting XML file...");
            if let Err(e) = encrypt_xml(&mut root, &key, &iv) {
                eprintln!("Error encrypting XML: {}", e);
                std::process::exit(1);
            }
        } else {
            eprintln!("Error: Unknown Cryptography status: {}", cryptography);
            std::process::exit(1);
        }

        // Restore attributes
        root.attributes.insert("ModelName".to_string(), model_name);
        root.attributes.insert("Version".to_string(), version_str);
        root.attributes.insert("Type".to_string(), type_str);

        let serialized = serialize_xml(&root, 0);
        if let Err(e) = std::fs::write(&output_path, serialized) {
            eprintln!("Error: Failed to write output XML file: {}", e);
            std::process::exit(1);
        }

        println!("Success! Processed file saved to: {}", output_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_output_filename() {
        assert_eq!(
            derive_output_filename("ThrottleGear_G614PR.xml", "Encrypted"),
            "ThrottleGear_G614PR_decrypted.xml"
        );
        assert_eq!(
            derive_output_filename("ThrottleGear_G614PR.xml", "Decrypted"),
            "ThrottleGear_G614PR_encrypted.xml"
        );
        assert_eq!(
            derive_output_filename("dir/subdir/ThrottleGear_G614PR.xml", "Encrypted"),
            "dir/subdir/ThrottleGear_G614PR_decrypted.xml"
        );
        assert_eq!(
            derive_output_filename("ThrottleGear_G614PR_decrypted.xml", "Decrypted"),
            "ThrottleGear_G614PR_encrypted.xml"
        );
        assert_eq!(
            derive_output_filename("ThrottleGear_G614PR_encrypted.xml", "Encrypted"),
            "ThrottleGear_G614PR_decrypted.xml"
        );
    }
}
