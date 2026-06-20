use std::collections::HashMap;
use crate::xml_processor::XmlElement;

pub fn validate_limits(
    ac_limits: &HashMap<String, i32>,
    dc_limits: &HashMap<String, i32>,
    gpu_base_tgp: i32,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if gpu_base_tgp < 30 || gpu_base_tgp > 200 {
        warnings.push(format!(
            "GPU base TGP ({}W) is outside the typical notebook range (30W-200W).",
            gpu_base_tgp
        ));
    }

    for (name, limits) in [("AC", ac_limits), ("DC", dc_limits)] {
        for (key, &val) in limits {
            if val < 0 {
                warnings.push(format!("[{}] {} has a negative value ({}).", name, key, val));
            }

            // Temperature bounds target
            if key.contains("temp_target") {
                if val < 0 || val > 100 {
                    warnings.push(format!(
                        "[{}] Temperature target {} ({}°C) is outside realistic range (0°C-100°C).",
                        name, key, val
                    ));
                }
            }

            // TGP bounds target
            if key.contains("tgp") {
                if val < 0 || val > 500 {
                    warnings.push(format!(
                        "[{}] GPU TGP {} ({}W) is outside typical range (0W-500W).",
                        name, key, val
                    ));
                }
            }
        }

        // Compare min/max / def
        let prefixes = [
            "ppt_pl1_spl",
            "ppt_pl2_sppt",
            "ppt_pl3_fppt",
            "ppt_apu_sppt",
            "ppt_platform_sppt",
            "nv_temp_target",
            "nv_dynamic_boost",
            "nv_tgp",
        ];

        for prefix in prefixes {
            let min_key = format!("{}_min", prefix);
            let max_key = format!("{}_max", prefix);
            let def_key = format!("{}_def", prefix);

            let min_val = limits.get(&min_key);
            let max_val = limits.get(&max_key);
            let def_val = limits.get(&def_key);

            if let (Some(&min), Some(&max)) = (min_val, max_val) {
                if min > max {
                    warnings.push(format!(
                        "[{}] Min limit {} ({}) is greater than max limit {} ({}).",
                        name, min_key, min, max_key, max
                    ));
                }

                if let Some(&def) = def_val {
                    if def < min || def > max {
                        warnings.push(format!(
                            "[{}] Default limit {} ({}) is outside [min, max] range [{}, {}].",
                            name, def_key, def, min, max
                        ));
                    }
                }
            }
        }
    }

    warnings
}

pub fn extract_cpu_limits(cpu_settings: &XmlElement, dc: bool) -> HashMap<String, i32> {
    let mut limits = HashMap::new();
    let overclock_items = match cpu_settings.find_child_recursive("OverclockItems") {
        Some(elem) => elem,
        None => return limits,
    };

    let prefix = if dc { "DC" } else { "" };
    let tags_and_fields = [
        ("STAPM", "ppt_pl1_spl"),
        ("PPTLimit", "ppt_pl2_sppt"),
        ("fPPTLimit", "ppt_pl3_fppt"),
        ("APUsPPTLimit", "ppt_apu_sppt"),
        ("PlatformsPPT", "ppt_platform_sppt"),
    ];

    for (tag, field) in tags_and_fields {
        if let Some(elem) = overclock_items.find_child_recursive(tag) {
            if elem.get_attribute("IsEnabled").map(|s| s.as_str()) == Some("True") {
                let lower_attr = format!("{}LowerLimit", prefix);
                let upper_attr = format!("{}UpperLimit", prefix);
                let manual_attr = format!("{}Manual", prefix);

                let min_val = elem.get_attribute(&lower_attr)
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0);
                let max_val = elem.get_attribute(&upper_attr)
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0);
                let def_val = elem.get_attribute(&manual_attr)
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0);

                if min_val != 0 || max_val != 0 {
                    limits.insert(format!("{}_min", field), min_val);
                    if def_val != max_val && def_val != 0 {
                        limits.insert(format!("{}_def", field), def_val);
                    }
                    limits.insert(format!("{}_max", field), max_val);
                }
            }
        }
    }

    limits
}

pub fn extract_gpu_limits(gpu_settings: &XmlElement, gpu_base_tgp: i32, dc: bool) -> HashMap<String, i32> {
    let mut limits = HashMap::new();
    let prefix = if dc { "DC" } else { "" };

    if let Some(gpu_overclock) = gpu_settings.find_child_recursive("NonSLIOverclockItems") {
        // NBThermalTarget
        if let Some(elem) = gpu_overclock.find_child_recursive("NBThermalTarget") {
            if elem.get_attribute("IsEnabled").map(|s| s.as_str()) == Some("True") {
                let lower_attr = format!("{}LowerLimit", prefix);
                let upper_attr = format!("{}UpperLimit", prefix);

                let min_val = elem.get_attribute(&lower_attr)
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0);
                let max_val = elem.get_attribute(&upper_attr)
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0);

                if min_val != 0 || max_val != 0 {
                    limits.insert("nv_temp_target_min".to_string(), min_val);
                    limits.insert("nv_temp_target_max".to_string(), max_val);
                }
            }
        }

        // DynamicBoost (AC only)
        if !dc {
            if let Some(elem) = gpu_overclock.find_child_recursive("DynamicBoost") {
                if elem.get_attribute("IsEnabled").map(|s| s.as_str()) == Some("True") {
                    let min_val = elem.get_attribute("LowerLimit")
                        .and_then(|s| s.parse::<i32>().ok())
                        .unwrap_or(0);
                    let max_val = elem.get_attribute("UpperLimit")
                        .and_then(|s| s.parse::<i32>().ok())
                        .unwrap_or(0);

                    if min_val != 0 || max_val != 0 {
                        limits.insert("nv_dynamic_boost_min".to_string(), min_val);
                        limits.insert("nv_dynamic_boost_max".to_string(), max_val);
                    }
                }
            }
        }
    }

    // TGP (AC only)
    if !dc {
        if let Some(tgp_items) = gpu_settings.find_child_recursive("NonSLITGPItems") {
            if let Some(elem) = tgp_items.find_child_recursive("TGPItem") {
                if elem.get_attribute("IsEnabled").map(|s| s.as_str()) == Some("True") {
                    let mut level_vals = Vec::new();
                    for (attr_name, attr_val) in &elem.attributes {
                        if attr_name.starts_with("Level") {
                            if let Ok(val) = attr_val.parse::<i32>() {
                                level_vals.push(val);
                            }
                        }
                    }
                    if !level_vals.is_empty() {
                        let min_offset = *level_vals.iter().min().unwrap();
                        let max_offset = *level_vals.iter().max().unwrap();
                        limits.insert("nv_tgp_min".to_string(), gpu_base_tgp + min_offset);
                        limits.insert("nv_tgp_max".to_string(), gpu_base_tgp + max_offset);
                    }
                }
            }
        }
    }

    limits
}

pub fn generate_c_struct(
    root: &XmlElement,
    profile: Option<&str>,
    gpu_base_tgp: i32,
    requires_fan_curve: bool,
) -> Result<(String, String), String> {
    let model_name = root.get_attribute("ModelName")
        .ok_or_else(|| "ModelName missing from XML attributes".to_string())?;

    // Identify profiles (child nodes containing CPU/GPU settings)
    let mut available_profiles = Vec::new();
    for child in &root.children {
        if let crate::xml_processor::XmlNode::Element(elem) = child {
            if elem.find_child_recursive("ThrottlePluginCPUSettings").is_some()
                || elem.find_child_recursive("ThrottlePluginGPUSettings").is_some()
            {
                available_profiles.push(&elem.name);
            }
        }
    }

    let mut profile_used = "Default".to_string();
    let (cpu_settings, gpu_settings) = if let Some(prof) = profile {
        let mut found_cpu = None;
        let mut found_gpu = None;
        for child in &root.children {
            if let crate::xml_processor::XmlNode::Element(elem) = child {
                if elem.name == prof {
                    found_cpu = elem.find_child_recursive("ThrottlePluginCPUSettings");
                    found_gpu = elem.find_child_recursive("ThrottlePluginGPUSettings");
                    profile_used = prof.to_string();
                    break;
                }
            }
        }
        if found_cpu.is_none() && found_gpu.is_none() {
            let mut err_msg = format!("Profile '{}' not found in XML.", prof);
            if !available_profiles.is_empty() {
                let list_profiles: Vec<String> = available_profiles.iter().map(|s| s.to_string()).collect();
                err_msg.push_str(&format!(" Available profiles: {}", list_profiles.join(", ")));
            }
            return Err(err_msg);
        }
        (found_cpu, found_gpu)
    } else {
        if available_profiles.len() > 1 {
            let list_profiles: Vec<String> = available_profiles.iter().map(|s| s.to_string()).collect();
            eprintln!(
                "Warning: Multiple profiles found in XML: {}. Defaulting to '{}'. Use -p/--profile to specify.",
                list_profiles.join(", "), available_profiles[0]
            );
            let mut found_cpu = None;
            let mut found_gpu = None;
            for child in &root.children {
                if let crate::xml_processor::XmlNode::Element(elem) = child {
                    if elem.name == *available_profiles[0] {
                        found_cpu = elem.find_child_recursive("ThrottlePluginCPUSettings");
                        found_gpu = elem.find_child_recursive("ThrottlePluginGPUSettings");
                        profile_used = available_profiles[0].to_string();
                        break;
                    }
                }
            }
            (found_cpu, found_gpu)
        } else if available_profiles.len() == 1 {
            let mut found_cpu = None;
            let mut found_gpu = None;
            for child in &root.children {
                if let crate::xml_processor::XmlNode::Element(elem) = child {
                    if elem.name == *available_profiles[0] {
                        found_cpu = elem.find_child_recursive("ThrottlePluginCPUSettings");
                        found_gpu = elem.find_child_recursive("ThrottlePluginGPUSettings");
                        profile_used = available_profiles[0].to_string();
                        break;
                    }
                }
            }
            (found_cpu, found_gpu)
        } else {
            (
                root.find_child_recursive("ThrottlePluginCPUSettings"),
                root.find_child_recursive("ThrottlePluginGPUSettings"),
            )
        }
    };

    let mut ac_limits = HashMap::new();
    if let Some(cpu) = cpu_settings {
        ac_limits.extend(extract_cpu_limits(cpu, false));
    }
    if let Some(gpu) = gpu_settings {
        ac_limits.extend(extract_gpu_limits(gpu, gpu_base_tgp, false));
    }

    let mut dc_limits = HashMap::new();
    if let Some(cpu) = cpu_settings {
        dc_limits.extend(extract_cpu_limits(cpu, true));
    }
    if let Some(gpu) = gpu_settings {
        dc_limits.extend(extract_gpu_limits(gpu, gpu_base_tgp, true));
    }

    let warnings = validate_limits(&ac_limits, &dc_limits, gpu_base_tgp);
    for warning in warnings {
        eprintln!("Warning: {}", warning);
    }

    let mut lines = Vec::new();
    lines.push("\t{".to_string());
    lines.push("\t\t.matches = {".to_string());
    lines.push(format!("\t\t\tDMI_MATCH(DMI_BOARD_NAME, \"{}\"),", model_name));
    lines.push("\t\t},".to_string());
    lines.push("\t\t.driver_data = &(struct power_data) {".to_string());

    if !ac_limits.is_empty() {
        lines.push("\t\t\t.ac_data = &(struct power_limits) {".to_string());
        let mut sorted_keys: Vec<&String> = ac_limits.keys().collect();
        sorted_keys.sort();
        for key in sorted_keys {
            let val = ac_limits.get(key).unwrap();
            lines.push(format!("\t\t\t\t.{} = {},", key, val));
        }
        lines.push("\t\t\t},".to_string());
    }

    if !dc_limits.is_empty() {
        lines.push("\t\t\t.dc_data = &(struct power_limits) {".to_string());
        let mut sorted_keys: Vec<&String> = dc_limits.keys().collect();
        sorted_keys.sort();
        for key in sorted_keys {
            let val = dc_limits.get(key).unwrap();
            lines.push(format!("\t\t\t\t.{} = {},", key, val));
        }
        lines.push("\t\t\t},".to_string());
    }

    let fan_curve_str = if requires_fan_curve { "true" } else { "false" };
    lines.push(format!("\t\t\t.requires_fan_curve = {},", fan_curve_str));
    lines.push("\t\t},".to_string());
    lines.push("\t},".to_string());

    Ok((lines.join("\n"), profile_used))
}
