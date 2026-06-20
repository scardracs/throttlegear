use std::collections::HashMap;
use crate::crypto::{decrypt_aes_256_cbc, encrypt_aes_256_cbc, base64_decode, base64_encode};

#[derive(Clone, Debug)]
pub struct XmlElement {
    pub name: String,
    pub attributes: HashMap<String, String>,
    pub children: Vec<XmlNode>,
}

#[derive(Clone, Debug)]
pub enum XmlNode {
    Element(XmlElement),
    Text(String),
}

impl XmlElement {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            attributes: HashMap::new(),
            children: Vec::new(),
        }
    }

    pub fn get_attribute(&self, key: &str) -> Option<&String> {
        self.attributes.get(key)
    }

    pub fn find_child_recursive<'a>(&'a self, name: &str) -> Option<&'a XmlElement> {
        if self.name == name || self.name.ends_with(&format!(":{}", name)) {
            return Some(self);
        }
        for child in &self.children {
            if let XmlNode::Element(elem) = child {
                if let Some(found) = elem.find_child_recursive(name) {
                    return Some(found);
                }
            }
        }
        None
    }
}

pub fn parse_xml_str(input: &str) -> Result<XmlElement, String> {
    let chars: Vec<char> = input.chars().collect();

    fn skip_whitespace(chars: &[char], pos: &mut usize) {
        while *pos < chars.len() && chars[*pos].is_whitespace() {
            *pos += 1;
        }
    }

    fn parse_element(chars: &[char], pos: &mut usize) -> Result<XmlElement, String> {
        skip_whitespace(chars, pos);
        if *pos >= chars.len() || chars[*pos] != '<' {
            return Err("Expected '<'".to_string());
        }
        *pos += 1; // skip '<'

        // Skip comments or metadata/doctype
        if *pos < chars.len() && (chars[*pos] == '!' || chars[*pos] == '?') {
            let is_comment = chars[*pos] == '!' && *pos + 2 < chars.len() && chars[*pos+1] == '-' && chars[*pos+2] == '-';
            if is_comment {
                *pos += 3;
                while *pos + 2 < chars.len() && !(chars[*pos] == '-' && chars[*pos+1] == '-' && chars[*pos+2] == '>') {
                    *pos += 1;
                }
                *pos += 3;
                skip_whitespace(chars, pos);
                return parse_element(chars, pos);
            }
            while *pos < chars.len() && chars[*pos] != '>' {
                *pos += 1;
            }
            if *pos < chars.len() {
                *pos += 1;
            }
            skip_whitespace(chars, pos);
            return parse_element(chars, pos);
        }

        // Read tag name
        let mut name = String::new();
        while *pos < chars.len() && !chars[*pos].is_whitespace() && chars[*pos] != '>' && chars[*pos] != '/' {
            name.push(chars[*pos]);
            *pos += 1;
        }

        let mut attributes = HashMap::new();
        loop {
            skip_whitespace(chars, pos);
            if *pos >= chars.len() {
                return Err("Unexpected EOF in attributes".to_string());
            }
            if chars[*pos] == '>' {
                *pos += 1;
                break;
            }
            if chars[*pos] == '/' && *pos + 1 < chars.len() && chars[*pos + 1] == '>' {
                *pos += 2;
                return Ok(XmlElement {
                    name,
                    attributes,
                    children: Vec::new(),
                });
            }

            // Read attribute name
            let mut attr_name = String::new();
            while *pos < chars.len() && !chars[*pos].is_whitespace() && chars[*pos] != '=' && chars[*pos] != '>' && chars[*pos] != '/' {
                attr_name.push(chars[*pos]);
                *pos += 1;
            }

            skip_whitespace(chars, pos);
            if *pos >= chars.len() || chars[*pos] != '=' {
                return Err(format!("Expected '=' after attribute '{}'", attr_name));
            }
            *pos += 1; // skip '='

            skip_whitespace(chars, pos);
            if *pos >= chars.len() || (chars[*pos] != '"' && chars[*pos] != '\'') {
                return Err("Expected quotes for attribute value".to_string());
            }
            let quote = chars[*pos];
            *pos += 1; // skip quote

            let mut attr_value = String::new();
            while *pos < chars.len() && chars[*pos] != quote {
                attr_value.push(chars[*pos]);
                *pos += 1;
            }
            if *pos >= chars.len() {
                return Err("Unexpected EOF inside attribute value".to_string());
            }
            *pos += 1; // skip quote

            attributes.insert(attr_name, attr_value);
        }

        let mut children = Vec::new();
        loop {
            let mut text = String::new();
            while *pos < chars.len() && chars[*pos] != '<' {
                text.push(chars[*pos]);
                *pos += 1;
            }
            if !text.trim().is_empty() {
                children.push(XmlNode::Text(text));
            }

            if *pos >= chars.len() {
                return Err(format!("Unclosed tag '{}'", name));
            }

            if *pos + 1 < chars.len() && chars[*pos + 1] == '/' {
                *pos += 2; // skip '</'
                let mut close_name = String::new();
                while *pos < chars.len() && chars[*pos] != '>' {
                    close_name.push(chars[*pos]);
                    *pos += 1;
                }
                if *pos >= chars.len() {
                    return Err("Expected '>' after closing tag name".to_string());
                }
                *pos += 1; // skip '>'
                let close_name = close_name.trim();
                if close_name != name {
                    return Err(format!("Mismatched tag: opened '{}', closed '{}'", name, close_name));
                }
                break;
            } else {
                let child_elem = parse_element(chars, pos)?;
                children.push(XmlNode::Element(child_elem));
            }
        }

        Ok(XmlElement {
            name,
            attributes,
            children,
        })
    }

    let mut pos = 0;
    parse_element(&chars, &mut pos)
}

pub fn serialize_xml(element: &XmlElement, indent_level: usize) -> String {
    let indent = "  ".repeat(indent_level);
    let mut attrs = String::new();

    // Sort attributes by key to match Python output structure
    let mut sorted_keys: Vec<&String> = element.attributes.keys().collect();
    sorted_keys.sort();
    for key in sorted_keys {
        attrs.push_str(&format!(" {}=\"{}\"", key, element.attributes.get(key).unwrap()));
    }

    if element.children.is_empty() {
        format!("{}<{}{} />", indent, element.name, attrs)
    } else {
        let mut children_str = String::new();
        let mut only_text = true;
        for child in &element.children {
            match child {
                XmlNode::Element(elem) => {
                    only_text = false;
                    children_str.push_str("\n");
                    children_str.push_str(&serialize_xml(elem, indent_level + 1));
                }
                XmlNode::Text(text) => {
                    children_str.push_str(text);
                }
            }
        }
        if only_text {
            format!("{}<{}{}>{}</{}>", indent, element.name, attrs, children_str, element.name)
        } else {
            format!("{}<{}{}>{}\n{}</{}>", indent, element.name, attrs, children_str, indent, element.name)
        }
    }
}

pub fn decrypt_xml(root: &mut XmlElement, key: &[u8]) -> Result<(), String> {
    let min_loader_version = root.get_attribute("MinLoaderVersion")
        .cloned()
        .unwrap_or_else(|| "5.7.7.0".to_string());

    let mut decrypted_children = Vec::new();

    for child_node in &root.children {
        if let XmlNode::Element(elem) = child_node {
            if elem.name.ends_with("EncryptedData") {
                // Find EncryptionMethod
                let enc_method = elem.find_child_recursive("EncryptionMethod")
                    .ok_or_else(|| "EncryptionMethod not found in EncryptedData".to_string())?;
                let algo = enc_method.get_attribute("Algorithm")
                    .ok_or_else(|| "Algorithm attribute missing".to_string())?;
                if algo != "http://www.w3.org/2001/04/xmlenc#aes256-cbc" {
                    return Err(format!("Unsupported algorithm: {}", algo));
                }

                // Find CipherValue
                let cipher_value = elem.find_child_recursive("CipherValue")
                    .ok_or_else(|| "CipherValue not found in EncryptedData".to_string())?;

                let cipher_text_node = cipher_value.children.get(0)
                    .ok_or_else(|| "CipherValue is empty".to_string())?;

                if let XmlNode::Text(b64_text) = cipher_text_node {
                    let full_ciphertext = base64_decode(b64_text)?;
                    if full_ciphertext.len() < 16 {
                        return Err("Ciphertext too short".to_string());
                    }

                    // Standard W3C: IV is prepended
                    let iv = &full_ciphertext[..16];
                    let ciphertext = &full_ciphertext[16..];

                    let decrypted_bytes = decrypt_aes_256_cbc(ciphertext, key, iv)?;
                    let decrypted_str = std::str::from_utf8(&decrypted_bytes)
                        .map_err(|e| format!("Decrypted string is not UTF-8: {}", e))?;

                    let decrypted_elem = parse_xml_str(decrypted_str)?;
                    decrypted_children.push(XmlNode::Element(decrypted_elem));
                }
            }
        }
    }

    if decrypted_children.is_empty() {
        return Err("No encrypted elements found".to_string());
    }

    root.children = decrypted_children;
    root.attributes.insert("MinLoaderVersion".to_string(), min_loader_version);
    root.attributes.insert("Cryptography".to_string(), "Decrypted".to_string());

    Ok(())
}

pub fn encrypt_xml(root: &mut XmlElement, key: &[u8], iv: &[u8]) -> Result<(), String> {
    let min_loader_version = root.get_attribute("MinLoaderVersion")
        .cloned()
        .unwrap_or_else(|| "5.7.7.0".to_string());

    let mut encrypted_children = Vec::new();
    let children_to_encrypt = root.children.clone();

    for child_node in children_to_encrypt {
        if let XmlNode::Element(ref elem) = child_node {
            // Serialize individual element to UTF-8
            let serialized = serialize_xml(elem, 0);
            let ciphertext = encrypt_aes_256_cbc(serialized.as_bytes(), key, iv)?;

            // W3C: prepend IV
            let mut payload = Vec::with_capacity(iv.len() + ciphertext.len());
            payload.extend_from_slice(iv);
            payload.extend_from_slice(&ciphertext);

            let payload_b64 = base64_encode(&payload);

            // Construct <EncryptedData Type="..." xmlns="...">
            let mut encrypted_data = XmlElement::new("EncryptedData");
            encrypted_data.attributes.insert("Type".to_string(), "http://www.w3.org/2001/04/xmlenc#Element".to_string());
            encrypted_data.attributes.insert("xmlns".to_string(), "http://www.w3.org/2001/04/xmlenc#".to_string());

            let mut enc_method = XmlElement::new("EncryptionMethod");
            enc_method.attributes.insert("Algorithm".to_string(), "http://www.w3.org/2001/04/xmlenc#aes256-cbc".to_string());
            encrypted_data.children.push(XmlNode::Element(enc_method));

            let mut cipher_data = XmlElement::new("CipherData");
            let mut cipher_value = XmlElement::new("CipherValue");
            cipher_value.children.push(XmlNode::Text(payload_b64));
            cipher_data.children.push(XmlNode::Element(cipher_value));

            encrypted_data.children.push(XmlNode::Element(cipher_data));
            encrypted_data.children.push(XmlNode::Text("\n".to_string())); // format helper

            encrypted_children.push(XmlNode::Element(encrypted_data));
        }
    }

    root.children = encrypted_children;
    root.attributes.insert("MinLoaderVersion".to_string(), min_loader_version);
    root.attributes.insert("Cryptography".to_string(), "Encrypted".to_string());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xml_parse_serialize() {
        let original_xml = "<Test attr1=\"val1\" attr2=\"val2\"><Child>Hello</Child></Test>";
        let parsed = parse_xml_str(original_xml).unwrap();
        assert_eq!(parsed.name, "Test");
        assert_eq!(parsed.attributes.get("attr1").unwrap(), "val1");
        
        let child = parsed.find_child_recursive("Child").unwrap();
        assert_eq!(child.name, "Child");
        
        let serialized = serialize_xml(&parsed, 0);
        assert!(serialized.contains("Hello"));
        assert!(serialized.contains("attr1=\"val1\""));
    }
}
