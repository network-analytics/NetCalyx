// Copyright (C) 2026-present The NetCalyx Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! XPath 1.0 subset text utilities.
//!
//! These are pure, schema-agnostic string functions over the restricted
//! XPath 1.0 grammar used by NETCONF/YANG-Push filters (plain location paths
//! with implicit `child`-axis steps and simple predicates) — no dependency
//! on a YANG context or any particular filter type. They back
//! [`crate::yang_push::filters::DatastoreXPathFilter::normalize_path`] and
//! [`crate::xml_utils::XmlParser::read_xpath_with_namespaces`], and are also
//! used outside this crate to diagnose xpath targets reported by a publisher
//! against a loaded schema.

use std::collections::HashSet;

/// Prefixes found in an XPath expression, split by how they were
/// referenced.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct XpathPrefixes {
    /// Used as an actual node/attribute-name reference (`prefix:name`
    /// outside a string literal). Always required, whether resolved via a
    /// declared `xmlns` binding or, if undeclared, as the module name
    /// itself (RFC 8641 base XPath context).
    pub(crate) structural: HashSet<String>,
    /// Seen only inside a string literal shaped like one whole QName (e.g.
    /// `hw-hwt` in `'hw-hwt:ethernetCsmacd-xcvr-link'`). Only meaningful
    /// with a declared `xmlns` binding (RFC 7950 §9.10.3); undeclared
    /// entries are likely incidental text and should be dropped, not
    /// resolved.
    pub(crate) literal_only: HashSet<String>,
}

impl XpathPrefixes {
    /// Whether `prefix` was referenced anywhere, regardless of category.
    pub(crate) fn contains(&self, prefix: &str) -> bool {
        self.structural.contains(prefix) || self.literal_only.contains(prefix)
    }
}

/// Find the prefixes used within an XPath expression (e.g. the `if` in
/// `/if:interfaces/if:interface`), split into [`XpathPrefixes::structural`]
/// (node/attribute-name references) and [`XpathPrefixes::literal_only`]
/// (whole-string QName-shaped literal values, e.g. `ianaift` in
/// `'ianaift:ethernetCsmacd'`). Axis specifiers (`child::`) are never
/// treated as prefixes. A literal that isn't shaped like a whole QName is
/// opaque data and contributes nothing.
pub(crate) fn find_xpath_prefixes(xpath: &str) -> XpathPrefixes {
    let mut prefixes = XpathPrefixes::default();
    let mut chars = xpath.char_indices().peekable();

    while let Some((i, c)) = chars.next() {
        match c {
            quote @ ('\'' | '"') => {
                let content_start = i + quote.len_utf8();
                let Some(rel_end) = xpath[content_start..].find(quote) else {
                    break; // unterminated literal (malformed xpath)
                };
                let content_end = content_start + rel_end;
                if let Some((Some(prefix), _)) = parse_node_test(&xpath[content_start..content_end])
                {
                    prefixes.literal_only.insert(prefix.to_string());
                }
                while chars.next_if(|&(idx, _)| idx < content_end).is_some() {}
                chars.next(); // consume the closing quote
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                let mut end = i + c.len_utf8();
                while let Some(&(_, nc)) = chars.peek() {
                    if nc.is_ascii_alphanumeric() || nc == '_' || nc == '-' || nc == '.' {
                        chars.next();
                        end += nc.len_utf8();
                    } else {
                        break;
                    }
                }
                // A prefix is an NCName followed by exactly one ':'
                // (two colons = axis specifier like `child::`).
                if let Some(&(_, ':')) = chars.peek() {
                    let mut look = chars.clone();
                    look.next();
                    let is_axis = matches!(look.peek(), Some(&(_, ':')));
                    if !is_axis {
                        prefixes.structural.insert(xpath[start..end].to_string());
                        chars.next(); // consume the ':'
                    }
                }
            }
            _ => {}
        }
    }
    prefixes
}

/// Split an xpath location path on `/` at bracket depth 0 and outside string
/// literals. Returns `None` if quotes or brackets are unbalanced.
pub(crate) fn split_location_path(path: &str) -> Option<Vec<&str>> {
    let mut segments = Vec::new();
    let mut depth: i32 = 0;
    let mut in_single = false;
    let mut in_double = false;
    let mut start = 0usize;
    for (i, c) in path.char_indices() {
        match c {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '[' if !in_single && !in_double => depth += 1,
            ']' if !in_single && !in_double => {
                depth -= 1;
                if depth < 0 {
                    return None;
                }
            }
            '/' if depth == 0 && !in_single && !in_double => {
                segments.push(&path[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if depth != 0 || in_single || in_double {
        return None;
    }
    segments.push(&path[start..]);
    Some(segments)
}

/// Parse a node test of the form `(prefix ':')? (NCName | '*')`, returning
/// `(prefix, local)`. Returns `None` for anything else (functions, axes, `@`,
/// `.`/`..`, embedded whitespace), which signals an unsupported path.
pub(crate) fn parse_node_test(head: &str) -> Option<(Option<&str>, &str)> {
    let head = head.trim();
    if head.is_empty() {
        return None;
    }
    let (prefix, local) = match head.split_once(':') {
        Some((p, l)) => (Some(p), l),
        None => (None, head),
    };
    if let Some(p) = prefix
        && !is_ncname(p)
    {
        return None;
    }
    if local != "*" && !is_ncname(local) {
        return None;
    }
    Some((prefix, local))
}

/// Whether `s` is a YANG/XML NCName: a leading letter or `_`, followed by
/// letters, digits, `_`, `-`, or `.`.
fn is_ncname(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Reduce `provided` vs `canonical` to the char index where they first
/// diverge, plus the substrings unique to each side (with the common
/// prefix/suffix stripped off), so small differences (e.g. a missing
/// leading slash) are obvious without scanning both full paths.
pub fn xpath_diff(provided: &str, canonical: &str) -> (usize, String, String) {
    let prefix_chars = provided
        .chars()
        .zip(canonical.chars())
        .take_while(|(a, b)| a == b)
        .count();
    let provided_chars = provided.chars().count();
    let canonical_chars = canonical.chars().count();
    let max_suffix = (provided_chars - prefix_chars).min(canonical_chars - prefix_chars);
    let suffix_chars = provided
        .chars()
        .rev()
        .zip(canonical.chars().rev())
        .take_while(|(a, b)| a == b)
        .count()
        .min(max_suffix);

    let byte_offset = |s: &str, chars: usize| -> usize {
        s.char_indices()
            .nth(chars)
            .map(|(i, _)| i)
            .unwrap_or(s.len())
    };
    let provided_unique = &provided
        [byte_offset(provided, prefix_chars)..byte_offset(provided, provided_chars - suffix_chars)];
    let canonical_unique = &canonical[byte_offset(canonical, prefix_chars)
        ..byte_offset(canonical, canonical_chars - suffix_chars)];

    (
        prefix_chars,
        provided_unique.to_string(),
        canonical_unique.to_string(),
    )
}

/// Remove XPath predicate groups (`[...]`) from a location path, honoring
/// quoted strings and nested brackets so predicate contents (including a
/// `]` inside a string literal) are not miscounted.
pub fn strip_xpath_predicates(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut depth: u32 = 0;
    let mut in_single = false;
    let mut in_double = false;
    for c in path.chars() {
        if depth == 0 {
            if c == '[' {
                depth = 1;
            } else {
                out.push(c);
            }
        } else {
            match c {
                '\'' if !in_double => in_single = !in_single,
                '"' if !in_single => in_double = !in_double,
                '[' if !in_single && !in_double => depth += 1,
                ']' if !in_single && !in_double => depth -= 1,
                _ => {}
            }
        }
    }
    // Unbalanced brackets/quotes: return the original rather than a
    // silently truncated path.
    if depth != 0 || in_single || in_double {
        return path.to_string();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_location_path_splits_on_slash_outside_brackets_and_quotes() {
        assert_eq!(
            split_location_path("/a/b[c='/']/d"),
            Some(vec!["", "a", "b[c='/']", "d"])
        );
    }

    #[test]
    fn test_split_location_path_rejects_unbalanced_brackets_or_quotes() {
        assert_eq!(split_location_path("/a[b"), None);
        assert_eq!(split_location_path("/a]"), None);
        assert_eq!(split_location_path("/a[b='c]"), None);
    }

    #[test]
    fn test_parse_node_test_accepts_prefixed_names_and_wildcards() {
        assert_eq!(
            parse_node_test("if:interface"),
            Some((Some("if"), "interface"))
        );
        assert_eq!(parse_node_test("*"), Some((None, "*")));
        assert_eq!(parse_node_test("if:*"), Some((Some("if"), "*")));
    }

    #[test]
    fn test_parse_node_test_rejects_functions_axes_and_special_steps() {
        for head in ["current()", "node()", "@id", ".", "..", "if : interface"] {
            assert_eq!(parse_node_test(head), None, "should reject `{head}`");
        }
    }

    #[test]
    fn test_is_ncname_accepts_valid_and_rejects_invalid_names() {
        for valid in ["if", "_ns", "oc-if", "a.b", "a1"] {
            assert!(is_ncname(valid), "should accept `{valid}`");
        }
        for invalid in ["", "1if", "-if", ".if", "if:name", "if name"] {
            assert!(!is_ncname(invalid), "should reject `{invalid}`");
        }
    }

    fn set<const N: usize>(items: [&str; N]) -> HashSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn assert_prefixes(expr: &str, expected: HashSet<String>) {
        let found = find_xpath_prefixes(expr);
        let all: HashSet<String> = found
            .structural
            .into_iter()
            .chain(found.literal_only)
            .collect();
        assert_eq!(all, expected, "unexpected prefix set for: {expr}");
    }

    #[test]
    fn test_find_xpath_prefixes_yields_empty_when_no_qnames_present() {
        // Empty/whitespace input, unprefixed paths, pure numeric/operator
        // expressions, the `current()` function, and bare node tests all
        // contain no QNames — so nothing should be reported.
        for expr in [
            "",
            "   \n\t",
            "/interfaces/interface/name",
            "1 + 2.5 - 3 <= 4 and 5 != 6",
            "current()",
            "node() | text() | comment() | processing-instruction()",
        ] {
            assert_prefixes(expr, HashSet::new());
        }
    }

    #[test]
    fn test_find_xpath_prefixes_test_extracts_prefixes_from_simple_location_paths() {
        // Motivating Huawei debug case, RFC 8641 Figure 12 (`/ex:foo`),
        // the subscribed-notifications `/int:interfaces` example,
        // prefix deduplication, and multi-prefix paths.
        let cases: &[(&str, HashSet<String>)] = &[
            (
                "/debug:debug/debug:board-resouce-states/debug:board-resouce-state",
                set(["debug"]),
            ),
            ("/ex:foo", set(["ex"])),
            ("/int:interfaces", set(["int"])),
            ("/if:interfaces/if:interface/if:name", set(["if"])),
            ("/a:x/b:y/c:z", set(["a", "b", "c"])),
        ];
        for (expr, expected) in cases {
            assert_prefixes(expr, expected.clone());
        }
    }

    #[test]
    fn test_find_xpath_prefixes_recognizes_full_ncname_charset_in_prefixes() {
        // NCName permits letters, digits, `_`, `-`, `.`
        // (the last three may not start the name).
        let cases: &[(&str, HashSet<String>)] = &[
            // Hyphenated — common in OpenConfig.
            (
                "/oc-if:interfaces/oc-if:interface[oc-if:name='eth0']",
                set(["oc-if"]),
            ),
            // Dot in the middle (legal NCName, rare in practice).
            ("/a.b:c", set(["a.b"])),
            // Underscore-leading.
            ("/_ns:leaf", set(["_ns"])),
        ];
        for (expr, expected) in cases {
            assert_prefixes(expr, expected.clone());
        }
    }

    #[test]
    fn test_find_xpath_prefixes_handles_prefixed_wildcards_and_attributes() {
        let cases: &[(&str, HashSet<String>)] = &[
            ("/ex:*", set(["ex"])),
            ("//@ex:id", set(["ex"])),
            ("/if:interface[@nc:operation='delete']", set(["if", "nc"])),
        ];
        for (expr, expected) in cases {
            assert_prefixes(expr, expected.clone());
        }
    }

    #[test]
    fn test_find_xpath_prefixes_xpath_axes_are_never_reported_as_prefixes() {
        // Every XPath 1.0 axis name followed by `::` must be skipped,
        // since the `::` is an axis separator rather than a prefix colon.
        const AXES: &[&str] = &[
            "ancestor",
            "ancestor-or-self",
            "attribute",
            "child",
            "descendant",
            "descendant-or-self",
            "following",
            "following-sibling",
            "namespace",
            "parent",
            "preceding",
            "preceding-sibling",
            "self",
        ];
        for axis in AXES {
            assert_prefixes(&format!("{axis}::node()"), HashSet::new());
        }
        // Axes can still coexist with real prefixes in the same expression.
        assert_prefixes("descendant::if:interface/child::if:name", set(["if"]));
    }

    #[test]
    fn test_find_xpath_prefixes_only_whole_qname_literals_are_reported() {
        // A colon inside a literal is only a prefix reference when the
        // *entire* literal is shaped like one QName (RFC 7950 §9.10
        // identityref lexical form) - a colon buried in a larger string, or
        // one with surrounding whitespace/extra separators, is just data.
        let cases: &[(&str, HashSet<String>)] = &[
            // Whole-literal QNames: reported, same as any other reference.
            ("../crypto = 'mc:aes'", set(["mc"])),
            ("name() = \"ns:bogus\"", set(["ns"])),
            ("@a:x = 'p:q' or @b:y = \"r:s\"", set(["a", "b", "p", "r"])),
            // Not a whole QName: colon is part of a larger string, skipped.
            ("@a:x = 'http://example.com:8080'", set(["a"])),
            ("contains(., 'note: value')", HashSet::new()),
            ("@a:x = 'a:b:c'", set(["a"])),
        ];
        for (expr, expected) in cases {
            assert_prefixes(expr, expected.clone());
        }
    }

    #[test]
    fn test_find_xpath_prefixes_reproduces_whole_qname_literal_subscriptions() {
        // `hw-hwt` appears only inside the literal value, never as a
        // node-name reference, but its module must still be fetched to
        // validate the comparison.
        assert_prefixes(
            "/hw:hardware/hw:component[hw-hw:sub-class='hw-hwt:ethernetCsmacd-xcvr-link']/bbf-hw-xcvr:transceiver-link",
            set(["hw", "hw-hw", "hw-hwt", "bbf-hw-xcvr"]),
        );

        // Two predicates in the same path, one with a whole-QName literal
        // (`ianahw`) and one with a plain literal (`'rpm'`, no colon) that
        // contributes nothing.
        assert_prefixes(
            "/hw:hardware/hw:component[hw:class='ianahw:sensor']/hw:sensor-data[hw:value-type='rpm']",
            set(["hw", "ianahw"]),
        );

        // The whole-QName literal predicate is the last step in the path,
        // with nothing after the closing `]`.
        assert_prefixes(
            "/if:interfaces/if:interface[if:type='ianaift:gpon']",
            set(["if", "ianaift"]),
        );
    }

    /// A prefix used as a node name lands in `structural`, a prefix seen
    /// only inside a whole-QName-shaped literal lands in `literal_only`.
    /// Whether the latter also has a declared binding is not this
    /// function's concern — it has no visibility into declared bindings —
    /// that gate lives with callers (e.g. `DatastoreXPathFilter::path_prefixes`).
    #[test]
    fn test_find_xpath_prefixes_splits_structural_from_literal_only() {
        let found = find_xpath_prefixes(
            "/hw:hardware/hw:component[hw-hw:sub-class='hw-hwt:ethernetCsmacd-xcvr-link']",
        );
        assert_eq!(found.structural, set(["hw", "hw-hw"]));
        assert_eq!(found.literal_only, set(["hw-hwt"]));
    }

    #[test]
    fn test_find_xpath_prefixes_handles_compound_expressions() {
        // Function calls, leafref-style predicates with current(),
        // unions, boolean ops across modules, and nested predicates.
        let cases: &[(&str, HashSet<String>)] = &[
            ("ex:size(@id)", set(["ex"])),
            (
                "/if:interfaces/if:interface[if:name = current()/../if:name]",
                set(["if"]),
            ),
            ("/a:foo | /b:bar", set(["a", "b"])),
            (
                "(/if:interfaces/if:interface/if:enabled = 'true') \
                 and count(/rt:routing/rt:routes) > 0",
                set(["if", "rt"]),
            ),
            ("/a:x[a:y[b:z = '1']/a:w = c:fn()]", set(["a", "b", "c"])),
        ];
        for (expr, expected) in cases {
            assert_prefixes(expr, expected.clone());
        }
    }

    #[test]
    fn test_find_xpath_prefixes_real_world_yang_expressions() {
        // ietf-interfaces-style `must`: `if:` is a live prefix, and the
        // `ianaift:*` tokens are whole-literal identityref QNames, so their
        // prefix is reported too (its module must be resolvable to validate
        // the comparison).
        let must_expr = "(/if:interfaces/if:interface[if:name=current()]/if:type \
                         = 'ianaift:ethernetCsmacd') \
                         or \
                         (/if:interfaces/if:interface[if:name=current()]/if:type \
                         = 'ianaift:ieee8023adLag')";
        assert_prefixes(must_expr, set(["if", "ianaift"]));

        // Multi-module subscriber filter for yp:datastore-xpath-filter.
        let filter_expr = "/if:interfaces/if:interface[if:name='eth0'] \
                           | /rt:routing/rt:ribs/rt:rib[rt:name=current()/ref:rib]";
        assert_prefixes(filter_expr, set(["if", "rt", "ref"]));
    }

    #[test]
    fn test_find_xpath_prefixes_whitespace_between_ncname_and_colon_breaks_qname() {
        // In XPath 1.0 a QName is lexically `NCName ':' NCName` with no
        // whitespace. `if : interfaces` is three tokens, so `if` must not
        // be reported as a prefix. This behavior is intentional.
        assert_prefixes("  /  if : interfaces  ", HashSet::new());
    }

    #[test]
    fn test_strip_xpath_predicates_removes_single_and_multiple_predicates() {
        assert_eq!(
            strip_xpath_predicates("/if:interfaces/if:interface[if:name='eth0']/if:oper-status"),
            "/if:interfaces/if:interface/if:oper-status"
        );
        assert_eq!(
            strip_xpath_predicates("/a:x[1]/a:y[a:z='w'][@id='2']"),
            "/a:x/a:y"
        );
    }

    #[test]
    fn test_strip_xpath_predicates_ignores_brackets_inside_string_literals() {
        // A `]` inside a quoted predicate value must not be mistaken for the
        // end of the predicate.
        assert_eq!(
            strip_xpath_predicates(r#"/a:x[a:y='[literal]']/a:z"#),
            "/a:x/a:z"
        );
    }

    #[test]
    fn test_strip_xpath_predicates_noop_without_predicates() {
        assert_eq!(
            strip_xpath_predicates("/if:interfaces/if:interface"),
            "/if:interfaces/if:interface"
        );
    }

    /// Unbalanced brackets/quotes must return the original path, not a
    /// silently truncated one.
    #[test]
    fn test_strip_xpath_predicates_unbalanced_input_returns_original() {
        for path in [
            "/if:interfaces/if:interface[if:name='eth0'",
            "/if:interfaces/if:interface[if:name='eth0]",
            "/a:x[a:y=\"unterminated]/a:z",
        ] {
            assert_eq!(strip_xpath_predicates(path), path);
        }
    }

    #[test]
    fn test_xpath_diff_reports_common_prefix_and_unique_suffixes() {
        let (diverges_at, provided_unique, canonical_unique) =
            xpath_diff("if:interfaces/interface", "/if:interfaces/interface");
        assert_eq!(diverges_at, 0);
        assert_eq!(provided_unique, "");
        assert_eq!(canonical_unique, "/");
    }

    #[test]
    fn test_xpath_diff_isolates_a_single_differing_segment() {
        let (diverges_at, provided_unique, canonical_unique) = xpath_diff(
            "/if:interfaces/if:interface/oper-status",
            "/if:interfaces/interface/oper-status",
        );
        assert_eq!(diverges_at, "/if:interfaces/i".chars().count());
        assert_eq!(provided_unique, "f:i");
        assert_eq!(canonical_unique, "");
    }

    #[test]
    fn test_xpath_diff_identical_paths_yield_no_unique_substrings() {
        let (diverges_at, provided_unique, canonical_unique) =
            xpath_diff("/if:interfaces/interface", "/if:interfaces/interface");
        assert_eq!(diverges_at, "/if:interfaces/interface".chars().count());
        assert!(provided_unique.is_empty());
        assert!(canonical_unique.is_empty());
    }
}
