//! Small text helpers shared by reports, stages and notification formatting.

/// Return at most `max_bytes` of `text`, ending on a UTF-8 character boundary.
pub fn truncate(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Like [`truncate`], but appends an ellipsis when the text is cut.
pub fn truncate_with_ellipsis(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    format!("{}…", truncate(text, max_bytes))
}

/// Visit each non-empty `key=value` line.
///
/// Full-line comments are ignored. When `strip_inline_comments` is set, everything from the first
/// `#` on a line is dropped as well, matching sysctl-style configuration files.
pub fn for_each_key_value(
    text: &str,
    strip_inline_comments: bool,
    mut visit: impl FnMut(&str, &str),
) {
    for line in text.lines() {
        let line = if strip_inline_comments {
            line.split('#').next().unwrap_or_default()
        } else {
            line
        };
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if !key.is_empty() {
            visit(key, value.trim());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_respects_character_boundaries() {
        let text = format!("{}é", "a".repeat(3));
        assert_eq!(truncate(&text, 4), "aaa");
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("é", 1), "");
    }

    #[test]
    fn ellipsis_is_only_added_when_text_is_cut() {
        assert_eq!(truncate_with_ellipsis("short", 10), "short");
        assert_eq!(truncate_with_ellipsis("longer", 4), "long…");
    }

    #[test]
    fn ellipsis_truncation_respects_character_boundaries() {
        let text = format!("{}é", "a".repeat(5));
        let truncated = truncate_with_ellipsis(&text, 6);
        assert!(truncated.ends_with('…'));
        assert!(truncated.is_char_boundary(truncated.len() - '…'.len_utf8()));
    }

    #[test]
    fn key_value_parser_handles_comments_and_empty_values() {
        let mut values = Vec::new();
        for_each_key_value(
            " A = one \n# skip\nB=two # trailing\nEMPTY=\n",
            true,
            |key, value| {
                values.push((key.to_owned(), value.to_owned()));
            },
        );
        assert_eq!(
            values,
            vec![
                ("A".to_owned(), "one".to_owned()),
                ("B".to_owned(), "two".to_owned()),
                ("EMPTY".to_owned(), String::new()),
            ]
        );
    }
}
