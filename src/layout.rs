//! Which keyboard layout a password is about to be typed in.
//!
//! Shown on the lock screen for the same reason Caps Lock is: a password
//! typed on `de` when the fingers expect `us` swaps `y` and `z`, and PAM
//! reports it as a wrong password — one `pam_faillock` attempt spent on
//! a password that was right.
//!
//! Read from the keymap the compositor hands this process rather than
//! asked of `hyprctl`, because the keymap is what the keystrokes will
//! actually be interpreted through. Nothing else can disagree with it.

/// The layouts in a keymap, in group order: `["us", "de"]` for a keymap
/// whose second group is German.
///
/// The keymap a compositor sends is *compiled*: xkbcommon flattens it,
/// so there is no `include "pc+us+de:2"` line to read — the first
/// version of this looked for one, passed its own tests, and found
/// nothing in a real keymap. What survives compilation is the symbols
/// section's name, `xkb_symbols "pc_us_de_2_inet(evdev)"`, where `_`
/// joins the components and a bare number is the group of the layout
/// before it; and one `name[N]="German";` line per group.
///
/// Layout codes are two or three lowercase letters, which is what tells
/// them apart from `pc` and from option fragments like `inet(evdev)`.
/// When the section name yields no codes, the groups' full names stand
/// in — "English (US)" is longer than `us` but it is still the answer.
pub fn layouts(keymap: &str) -> Vec<String> {
    let Some(section) = keymap.split("xkb_symbols").nth(1) else {
        return Vec::new();
    };
    let title = section.split('"').nth(1).unwrap_or("");
    let codes = codes(title);
    if !codes.is_empty() {
        return codes;
    }
    // `name[1]="English (US)";`, in group order.
    let body = section.split('{').nth(1).unwrap_or("");
    let mut named: Vec<(usize, String)> = body
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("name[")?;
            let (index, rest) = rest.split_once(']')?;
            let group = index.trim().trim_start_matches("Group").parse::<usize>().ok()?;
            let value = rest.split('"').nth(1)?;
            Some((group, value.to_string()))
        })
        .collect();
    named.sort_by_key(|(group, _)| *group);
    named.into_iter().map(|(_, name)| name).collect()
}

/// Layout codes from a compiled symbols section's name.
fn codes(title: &str) -> Vec<String> {
    let mut groups: Vec<(usize, String)> = Vec::new();
    let parts = components(title);
    let mut i = 0;
    while i < parts.len() {
        let part = parts[i];
        let base = part.split('(').next().unwrap_or("");
        let is_layout =
            (2..=3).contains(&base.len()) && base.bytes().all(|b| b.is_ascii_lowercase()) && base != "pc";
        if is_layout {
            // A number right after a layout is its group; none means
            // group one.
            let group = parts.get(i + 1).and_then(|next| next.parse::<usize>().ok());
            if group.is_some() {
                i += 1;
            }
            let group = group.unwrap_or(1);
            if !groups.iter().any(|(g, _)| *g == group) {
                groups.push((group, base.to_string()));
            }
        }
        i += 1;
    }
    groups.sort_by_key(|(group, _)| *group);
    groups.into_iter().map(|(_, name)| name).collect()
}

/// Splits on `_`, except inside parentheses: `level3(ralt_switch)` is one
/// component, not two.
fn components(title: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0usize, 0usize);
    for (i, c) in title.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            '_' if depth == 0 => {
                parts.push(&title[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&title[start..]);
    parts.into_iter().filter(|p| !p.is_empty()).collect()
}

/// The active layout's name, given the group index the compositor sent
/// with the modifiers. `None` for a group the keymap does not name,
/// which is better said as nothing than as the wrong layout.
pub fn active(layouts: &[String], group: u32) -> Option<String> {
    layouts.get(group as usize).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape `xkbcli compile-keymap` and every compositor produce —
    /// copied from a real one, because the first version of this module
    /// was tested against a format no compositor sends.
    fn compiled(title: &str, names: &[&str]) -> String {
        let names: String =
            names.iter().enumerate().map(|(i, n)| format!("\tname[{}]=\"{n}\";\n", i + 1)).collect();
        format!(
            "xkb_keymap {{\nxkb_keycodes \"evdev_aliases(qwerty)\" {{\n\tminimum = 8;\n}};\n\
             xkb_symbols \"{title}\" {{\n{names}\tkey <TLDE> {{ [ grave, asciitilde ] }};\n}};\n}};\n"
        )
    }

    #[test]
    fn a_single_layout_is_found_in_a_compiled_keymap() {
        assert_eq!(layouts(&compiled("pc_us_inet(evdev)", &["English (US)"])), vec!["us"]);
    }

    #[test]
    fn extra_groups_come_back_in_group_order() {
        assert_eq!(
            layouts(&compiled("pc_us_de_2_inet(evdev)", &["English (US)", "German"])),
            vec!["us", "de"]
        );
        assert_eq!(layouts(&compiled("pc_gb_us_2_fr(azerty)_3_inet(evdev)", &[])), vec!["gb", "us", "fr"]);
    }

    /// A variant is still the layout: `us(intl)` is typed as `us` with
    /// dead keys, and saying `us` is the useful half of that.
    #[test]
    fn a_variant_reports_its_layout() {
        assert_eq!(layouts(&compiled("pc_us(intl)_inet(evdev)", &[])), vec!["us"]);
    }

    /// Option fragments carry underscores of their own inside their
    /// parentheses, and none of them may be mistaken for a layout.
    #[test]
    fn option_fragments_are_never_layouts() {
        assert_eq!(
            layouts(&compiled("pc_us_inet(evdev)_level3(ralt_switch)_compose(menu)_terminate(ctrl_alt_bksp)", &[])),
            vec!["us"]
        );
    }

    /// A section name with nothing recognisable in it still has the
    /// groups' own names.
    #[test]
    fn full_names_stand_in_when_no_code_can_be_read() {
        assert_eq!(layouts(&compiled("custom", &["English (US)", "German"])), vec!["English (US)", "German"]);
    }

    #[test]
    fn a_keymap_without_symbols_names_no_layout_rather_than_guessing() {
        assert!(layouts("").is_empty());
        assert!(layouts("xkb_keymap { xkb_keycodes \"evdev\" { }; };").is_empty());
        assert_eq!(active(&["us".into()], 1), None);
        assert_eq!(active(&["us".into(), "de".into()], 1), Some("de".into()));
    }

    /// Against the system's own compiler, when it is installed: the one
    /// check that this reads what xkbcommon actually writes.
    #[test]
    fn the_systems_own_compiled_keymap_is_read() {
        let mut command = std::process::Command::new("xkbcli");
        command.args(["compile-keymap", "--layout", "us,de"]);
        let Ok(output) = hyprforge_process::output(&mut command, hyprforge_process::TIMEOUT) else {
            eprintln!("HYPRFORGE-SKIP: xkbcli isn't installed");
            return;
        };
        let keymap = String::from_utf8_lossy(&output.stdout);
        assert_eq!(layouts(&keymap), vec!["us", "de"]);
    }
}
