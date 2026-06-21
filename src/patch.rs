use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

struct Entry {
    board_name: Option<String>,
    start_idx: usize,
    end_idx: usize,
}

fn find_best_entry<'a>(entries: &'a [Entry], model_name: &str) -> (Option<&'a Entry>, Option<String>) {
    for entry in entries {
        if entry.board_name.as_deref() == Some(model_name) {
            return (Some(entry), None);
        }
    }

    let mut best_prefix: Option<&Entry> = None;
    for entry in entries {
        if let Some(ref board) = entry.board_name {
            if model_name.starts_with(board) {
                if let Some(curr) = best_prefix {
                    if board.len() > curr.board_name.as_ref().unwrap().len() {
                        best_prefix = Some(entry);
                    }
                } else {
                    best_prefix = Some(entry);
                }
            }
        }
    }

    if let Some(entry) = best_prefix {
        (Some(entry), entry.board_name.clone())
    } else {
        (None, None)
    }
}

fn parse_line_field_and_val(line: &str) -> Option<(String, i32)> {
    let dot_idx = line.find('.')?;
    let eq_idx = line[dot_idx..].find('=')?;
    let field = line[dot_idx + 1..dot_idx + eq_idx].trim().to_string();
    let val_str: String = line[dot_idx + eq_idx + 1..]
        .chars()
        .take_while(|c| c.is_digit(10) || *c == '-')
        .collect();
    let val = val_str.trim().parse::<i32>().ok()?;
    Some((field, val))
}

fn update_existing_entry_in_place(
    existing_lines: &[String],
    new_ac: &HashMap<String, i32>,
    new_dc: &HashMap<String, i32>,
    new_fan: Option<bool>,
    superseded_model: Option<&str>,
) -> Vec<String> {
    let mut updated = Vec::new();
    let mut in_ac = false;
    let mut in_dc = false;
    let mut in_driver_data = false;

    let mut processed_ac = HashMap::new();
    let mut processed_dc = HashMap::new();
    let mut processed_fan = false;

    for line in existing_lines {
        // Track sections
        if line.contains(".driver_data") {
            in_driver_data = true;
        }
        if line.contains(".ac_data") {
            in_ac = true;
        } else if line.contains(".dc_data") {
            in_dc = true;
        }

        // Check if we match the board name DMI match line
        if line.contains("DMI_MATCH(DMI_BOARD_NAME,") {
            if let Some(superseded) = superseded_model {
                updated.push(format!("\t\t\tDMI_MATCH(DMI_BOARD_NAME, \"{}\"),", superseded));
                continue;
            }
        }

        // Handle limits fields
        if in_ac || in_dc {
            if let Some((field, old_val)) = parse_line_field_and_val(line) {
                let new_val_opt = if in_ac {
                    new_ac.get(&field)
                } else {
                    new_dc.get(&field)
                };

                if let Some(&new_val) = new_val_opt {
                    if in_ac {
                        processed_ac.insert(field.clone(), true);
                    } else {
                        processed_dc.insert(field.clone(), true);
                    }

                    if new_val == old_val {
                        updated.push(line.clone());
                    } else {
                        let indent = line.chars().take_while(|c| c.is_whitespace()).collect::<String>();
                        updated.push(format!("{}.{} = {},", indent, field, new_val));
                    }
                    continue;
                }
            }
        }

        // Handle requires_fan_curve
        if in_driver_data && line.contains("requires_fan_curve") {
            if let Some(fan) = new_fan {
                processed_fan = true;
                let old_fan = line.contains("true");
                if fan == old_fan {
                    updated.push(line.clone());
                } else {
                    let indent = line.chars().take_while(|c| c.is_whitespace()).collect::<String>();
                    updated.push(format!("{}.requires_fan_curve = {},", indent, fan));
                }
                continue;
            }
        }

        // Check if closing brace of ac_data or dc_data
        if in_ac && line.trim().starts_with('}') {
            let indent = line.chars().take_while(|c| c.is_whitespace()).collect::<String>();
            let mut keys: Vec<&String> = new_ac.keys().collect();
            keys.sort();
            for key in keys {
                if !processed_ac.contains_key(key) {
                    updated.push(format!("\t{}.{} = {},", indent, key, new_ac.get(key).unwrap()));
                }
            }
            in_ac = false;
        }

        if in_dc && line.trim().starts_with('}') {
            let indent = line.chars().take_while(|c| c.is_whitespace()).collect::<String>();
            let mut keys: Vec<&String> = new_dc.keys().collect();
            keys.sort();
            for key in keys {
                if !processed_dc.contains_key(key) {
                    updated.push(format!("\t{}.{} = {},", indent, key, new_dc.get(key).unwrap()));
                }
            }
            in_dc = false;
        }

        // Check if closing brace of driver_data
        if in_driver_data && line.trim() == "}," && !in_ac && !in_dc {
            let tab_count = line.chars().take_while(|c| *c == '\t').count();
            let space_count = line.chars().take_while(|c| *c == ' ').count();
            if tab_count == 2 || space_count == 8 {
                if let Some(fan) = new_fan {
                    if !processed_fan {
                        updated.push(format!("\t\t\t.requires_fan_curve = {},", fan));
                        processed_fan = true;
                    }
                }
                in_driver_data = false;
            }
        }

        updated.push(line.clone());
    }

    updated
}

fn parse_c_struct_limits(
    c_struct_lines: &[String],
) -> (HashMap<String, i32>, HashMap<String, i32>, Option<bool>) {
    let mut ac_limits = HashMap::new();
    let mut dc_limits = HashMap::new();
    let mut fan_curve = None;
    let mut current_section = None;

    for line in c_struct_lines {
        if line.contains(".ac_data") {
            current_section = Some("AC");
        } else if line.contains(".dc_data") {
            current_section = Some("DC");
        } else if line.contains("requires_fan_curve") {
            if line.contains("true") {
                fan_curve = Some(true);
            } else if line.contains("false") {
                fan_curve = Some(false);
            }
        } else {
            // Find .field = value,
            if let Some(dot_idx) = line.find('.') {
                if let Some(eq_idx) = line[dot_idx..].find('=') {
                    let field = line[dot_idx + 1..dot_idx + eq_idx].trim();
                    let val_str: String = line[dot_idx + eq_idx + 1..]
                        .chars()
                        .take_while(|c| c.is_digit(10) || *c == '-')
                        .collect();
                    if let Ok(val) = val_str.trim().parse::<i32>() {
                        if current_section == Some("AC") {
                            ac_limits.insert(field.to_string(), val);
                        } else if current_section == Some("DC") {
                            dc_limits.insert(field.to_string(), val);
                        }
                    }
                }
            }
        }
    }
    (ac_limits, dc_limits, fan_curve)
}

pub fn generate_unified_diff(
    original: &[String],
    modified: &[String],
    filename: &str,
) -> (String, usize, usize) {
    let mut prefix_len = 0;
    while prefix_len < original.len() && prefix_len < modified.len() && original[prefix_len] == modified[prefix_len] {
        prefix_len += 1;
    }

    let mut suffix_len = 0;
    while suffix_len < original.len() - prefix_len
        && suffix_len < modified.len() - prefix_len
        && original[original.len() - 1 - suffix_len] == modified[modified.len() - 1 - suffix_len]
    {
        suffix_len += 1;
    }

    let orig_mid_start = prefix_len;
    let orig_mid_end = original.len() - suffix_len;
    let mod_mid_start = prefix_len;
    let mod_mid_end = modified.len() - suffix_len;

    let context_before = 3;
    let context_after = 3;

    let start_context_idx = if orig_mid_start > context_before {
        orig_mid_start - context_before
    } else {
        0
    };
    let end_context_idx = if orig_mid_end + context_after < original.len() {
        orig_mid_end + context_after
    } else {
        original.len()
    };

    let mut diff = Vec::new();
    diff.push(format!("--- a/{}", filename));
    diff.push(format!("+++ b/{}", filename));

    let orig_len = end_context_idx - start_context_idx;
    let mod_len = (orig_mid_start - start_context_idx)
        + (mod_mid_end - mod_mid_start)
        + (end_context_idx - orig_mid_end);

    diff.push(format!(
        "@@ -{},{} +{},{} @@",
        start_context_idx + 1,
        orig_len,
        start_context_idx + 1,
        mod_len
    ));

    for i in start_context_idx..orig_mid_start {
        diff.push(format!(" {}", original[i]));
    }

    let mut deletions = 0;
    for i in orig_mid_start..orig_mid_end {
        diff.push(format!("-{}", original[i]));
        deletions += 1;
    }

    let mut additions = 0;
    for i in mod_mid_start..mod_mid_end {
        diff.push(format!("+{}", modified[i]));
        additions += 1;
    }

    for i in orig_mid_end..end_context_idx {
        diff.push(format!(" {}", original[i]));
    }

    (diff.join("\n"), additions, deletions)
}

pub fn generate_patch_file(
    model_name: &str,
    profile_name: &str,
    c_struct_str: &str,
    author: &str,
    sob: &str,
    kernel_dir: Option<&str>,
    patch_dir: Option<&str>,
) -> Result<(), String> {
    let header_content = if let Some(dir) = kernel_dir {
        let path = Path::new(dir).join("drivers/platform/x86/asus-armoury.h");
        if !path.exists() {
            return Err(format!("Local header not found at: {:?}", path));
        }
        fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read local header: {}", e))?
    } else {
        println!("Fetching mainline asus-armoury.h via curl...");
        let output = Command::new("curl")
            .arg("-sSf")
            .arg("https://raw.githubusercontent.com/torvalds/linux/master/drivers/platform/x86/asus-armoury.h")
            .output()
            .map_err(|e| format!("Failed to execute curl: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "Failed to download header (exit status: {}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        String::from_utf8(output.stdout)
            .map_err(|e| format!("Mainline header is not valid UTF-8: {}", e))?
    };

    let lines: Vec<String> = header_content.lines().map(|s| s.to_string()).collect();

    let mut start_idx = None;
    for (i, line) in lines.iter().enumerate() {
        if line.contains("static const struct dmi_system_id power_limits[]") {
            start_idx = Some(i);
            break;
        }
    }
    let start_idx = start_idx.ok_or("Could not find power_limits table in asus-armoury.h")?;

    let mut entries = Vec::new();
    let mut current_entry_start = None;
    let mut current_board_name = None;
    let mut brace_depth = 0;
    let mut array_end_idx = None;

    for i in (start_idx + 1)..lines.len() {
        let line = &lines[i];

        if line.contains("};") && brace_depth == 0 {
            array_end_idx = Some(i);
            break;
        }

        let open_braces = line.matches('{').count();
        let close_braces = line.matches('}').count();

        if brace_depth == 0 && open_braces > 0 {
            current_entry_start = Some(i);
            current_board_name = None;
        }

        brace_depth += open_braces as i32 - close_braces as i32;

        if brace_depth == 0 && current_entry_start.is_some() {
            entries.push(Entry {
                board_name: current_board_name.clone(),
                start_idx: current_entry_start.unwrap(),
                end_idx: i,
            });
            current_entry_start = None;
            current_board_name = None;
        }

        if brace_depth > 0 {
            if let Some(start) = line.find("DMI_MATCH(DMI_BOARD_NAME,") {
                if let Some(quote_start) = line[start..].find('"') {
                    let actual_quote_start = start + quote_start + 1;
                    if let Some(quote_end) = line[actual_quote_start..].find('"') {
                        let board = &line[actual_quote_start..actual_quote_start + quote_end];
                        current_board_name = Some(board.to_string());
                    }
                }
            }
        }
    }
    let array_end_idx = array_end_idx.ok_or("Could not find end of power_limits table in asus-armoury.h")?;

    let c_struct_lines: Vec<String> = c_struct_str.lines().map(|s| s.to_string()).collect();

    let (existing_entry, superseded_by) = find_best_entry(&entries, model_name);

    let new_lines = if let Some(entry) = existing_entry {
        if let Some(ref superseded_model) = superseded_by {
            println!("\n[INFO] Quirk for model '{}' is superseded by existing entry '{}' in asus-armoury.h.", model_name, superseded_model);
        } else {
            println!("\n[INFO] Quirk for model '{}' already exists in asus-armoury.h.", model_name);
        }

        let (existing_ac, existing_dc, existing_fan) = parse_c_struct_limits(&lines[entry.start_idx..=entry.end_idx]);
        let (new_ac, new_dc, new_fan) = parse_c_struct_limits(&c_struct_lines);

        let mut differences = Vec::new();
        let mut all_ac_keys: Vec<&String> = existing_ac.keys().collect();
        for k in new_ac.keys() {
            if !all_ac_keys.contains(&k) {
                all_ac_keys.push(k);
            }
        }
        all_ac_keys.sort();

        for key in all_ac_keys {
            let old_val = existing_ac.get(key);
            let new_val = new_ac.get(key);
            if old_val != new_val {
                differences.push(format!(
                    "AC limit '{}': mainline has {:?}, generated has {:?}",
                    key, old_val, new_val
                ));
            }
        }

        let mut all_dc_keys: Vec<&String> = existing_dc.keys().collect();
        for k in new_dc.keys() {
            if !all_dc_keys.contains(&k) {
                all_dc_keys.push(k);
            }
        }
        all_dc_keys.sort();

        for key in all_dc_keys {
            let old_val = existing_dc.get(key);
            let new_val = new_dc.get(key);
            if old_val != new_val {
                differences.push(format!(
                    "DC limit '{}': mainline has {:?}, generated has {:?}",
                    key, old_val, new_val
                ));
            }
        }

        if existing_fan != new_fan {
            differences.push(format!(
                "requires_fan_curve: mainline has {:?}, generated has {:?}",
                existing_fan, new_fan
            ));
        }

        if !differences.is_empty() {
            println!("Differences compared to mainline:");
            for diff in differences {
                println!("  - {}", diff);
            }
        } else {
            println!("No differences found compared to mainline.");
        }

        let final_c_struct_lines = update_existing_entry_in_place(
            &lines[entry.start_idx..=entry.end_idx],
            &new_ac,
            &new_dc,
            new_fan,
            superseded_by.as_deref(),
        );

        let mut res = Vec::new();
        res.extend_from_slice(&lines[..entry.start_idx]);
        res.extend_from_slice(&final_c_struct_lines);
        res.extend_from_slice(&lines[entry.end_idx + 1..]);
        res
    } else {
        let mut insert_line_idx = None;
        for entry in &entries {
            if let Some(ref board) = entry.board_name {
                if board > &model_name.to_string() {
                    insert_line_idx = Some(entry.start_idx);
                    break;
                }
            }
        }
        let insert_line_idx = insert_line_idx.unwrap_or(array_end_idx);

        let mut res = Vec::new();
        res.extend_from_slice(&lines[..insert_line_idx]);
        res.extend_from_slice(&c_struct_lines);
        res.extend_from_slice(&lines[insert_line_idx..]);
        res
    };

    let file_rel_path = "drivers/platform/x86/asus-armoury.h";
    let (diff_str, additions, deletions) = generate_unified_diff(&lines, &new_lines, file_rel_path);

    let total_changes = additions + deletions;
    let stat_bar = format!("{}{}", "+".repeat(additions), "-".repeat(deletions));
    let stat_line = format!(" {} | {} {}", file_rel_path, total_changes, stat_bar);

    let summary_line = if additions > 0 && deletions > 0 {
        format!(" 1 file changed, {} insertions(+), {} deletions(-)", additions, deletions)
    } else if additions > 0 {
        format!(" 1 file changed, {} insertions(+)", additions)
    } else if deletions > 0 {
        format!(" 1 file changed, {} deletions(-)", deletions)
    } else {
        " 0 files changed".to_string()
    };

    let local_time = Command::new("date")
        .arg("+%a, %d %b %Y %H:%M:%S %z")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "Mon, 01 Jan 2000 00:00:00 +0000".to_string());

    let action_str = if existing_entry.is_some() { "Update" } else { "Add" };
    let target_model = superseded_by.as_deref().unwrap_or(model_name);

    let patch_content = format!(
        "From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\n\
         From: {}\n\
         Date: {}\n\
         Subject: [PATCH] platform/x86: asus-armoury: {} power limits quirk for {}\n\
         \n\
         {} power limits quirk entry for ASUS ROG {} laptop.\n\
         The limits are extracted from the device's ThrottleGear XML configuration\n\
         file for the '{}' profile.\n\
         \n\
         Assisted-by: ThrottleGear\n\
         Signed-off-by: {}\n\
         ---\n\
         {}\n\
         {}\n\
         \n\
         {}\n\
         -- \n\
         2.54.0\n",
        author, local_time, action_str, target_model, action_str, target_model, profile_name, sob, stat_line, summary_line, diff_str
    );

    let pdir = patch_dir.unwrap_or("patches");
    let model_patch_dir = Path::new(pdir).join(model_name);
    fs::create_dir_all(&model_patch_dir)
        .map_err(|e| format!("Failed to create patch directory: {}", e))?;

    let patch_file_path = model_patch_dir.join(format!(
        "0001-platform-x86-asus-armoury-add-power-limits-for-{}.patch",
        model_name
    ));

    fs::write(&patch_file_path, patch_content)
        .map_err(|e| format!("Failed to write patch file: {}", e))?;

    println!("Success! Kernel patch saved to: {:?}", patch_file_path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_best_entry() {
        let entries = vec![
            Entry {
                board_name: Some("GU604V".to_string()),
                start_idx: 10,
                end_idx: 20,
            },
            Entry {
                board_name: Some("GU604".to_string()),
                start_idx: 30,
                end_idx: 40,
            },
            Entry {
                board_name: Some("G614PR".to_string()),
                start_idx: 50,
                end_idx: 60,
            },
        ];

        // Exact match
        let (entry, superseded) = find_best_entry(&entries, "G614PR");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().start_idx, 50);
        assert!(superseded.is_none());

        // Prefix match (superseded by GU604V)
        let (entry, superseded) = find_best_entry(&entries, "GU604VI");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().start_idx, 10);
        assert_eq!(superseded, Some("GU604V".to_string()));

        // Broader prefix match (superseded by GU604)
        let (entry, superseded) = find_best_entry(&entries, "GU604A");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().start_idx, 30);
        assert_eq!(superseded, Some("GU604".to_string()));

        // No match
        let (entry, superseded) = find_best_entry(&entries, "GU502");
        assert!(entry.is_none());
        assert!(superseded.is_none());
    }

    #[test]
    fn test_update_existing_entry_in_place() {
        let existing = vec![
            "\t{".to_string(),
            "\t\t.matches = {".to_string(),
            "\t\t\tDMI_MATCH(DMI_BOARD_NAME, \"GU604V\"),".to_string(),
            "\t\t},".to_string(),
            "\t\t.driver_data = &(struct power_data) {".to_string(),
            "\t\t\t.ac_data = &(struct power_limits) {".to_string(),
            "\t\t\t\t.ppt_pl1_spl_min = 65,".to_string(),
            "\t\t\t\t.ppt_pl1_spl_max = 120,".to_string(),
            "\t\t\t},".to_string(),
            "\t\t\t.dc_data = &(struct power_limits) {".to_string(),
            "\t\t\t\t.ppt_pl1_spl_min = 25,".to_string(),
            "\t\t\t\t.ppt_pl1_spl_max = 40,".to_string(),
            "\t\t\t\t.ppt_pl2_sppt_def = 40,".to_string(),
            "\t\t\t},".to_string(),
            "\t\t},".to_string(),
            "\t},".to_string(),
        ];

        let mut new_ac = HashMap::new();
        new_ac.insert("ppt_pl1_spl_min".to_string(), 65); // identical
        new_ac.insert("ppt_pl1_spl_max".to_string(), 130); // modified

        let mut new_dc = HashMap::new();
        new_dc.insert("ppt_pl1_spl_min".to_string(), 25); // identical
        new_dc.insert("ppt_pl1_spl_max".to_string(), 40); // identical

        let updated = update_existing_entry_in_place(
            &existing,
            &new_ac,
            &new_dc,
            Some(true),
            Some("GU604V"),
        );

        // Verification:
        // 1. DMI match line preserved as GU604V
        assert!(updated.iter().any(|l| l.contains("DMI_MATCH(DMI_BOARD_NAME, \"GU604V\")")));
        // 2. AC pl1_spl_max updated to 130
        assert!(updated.iter().any(|l| l.contains(".ppt_pl1_spl_max = 130")));
        // 3. DC pl2_sppt_def preserved
        assert!(updated.iter().any(|l| l.contains(".ppt_pl2_sppt_def = 40")));
        // 4. requires_fan_curve appended
        assert!(updated.iter().any(|l| l.contains(".requires_fan_curve = true")));
    }
}
