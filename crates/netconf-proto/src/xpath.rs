// Copyright (C) 2026-present The NetCalyx Authors.
// Copyright (C) 2026-present The NetGauze Authors.
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
//! [`crate::yang_push::filters::DatastoreXPathFilter::path_prefixes`] and
//! [`crate::xml_utils::XmlParser::read_xpath_with_namespaces`].

use std::collections::HashSet;

/// Find the prefixes used within an Xpath expression (e.g. the `if` in
/// `/if:interfaces/if:interface`). String literals are skipped and axis
/// specifiers (`child::`) are not treated as prefixes.
pub(crate) fn find_xpath_prefixes(xpath: &str) -> HashSet<String> {
    let mut prefixes = HashSet::new();
    let mut chars = xpath.char_indices().peekable();
    let mut in_single = false;
    let mut in_double = false;

    while let Some((i, c)) = chars.next() {
        // Skip over string literals — colons inside them aren't prefixes.
        if in_single {
            if c == '\'' {
                in_single = false;
            }
            continue;
        }
        if in_double {
            if c == '"' {
                in_double = false;
            }
            continue;
        }
        match c {
            '\'' => in_single = true,
            '"' => in_double = true,
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
                        prefixes.insert(xpath[start..end].to_string());
                        chars.next(); // consume the ':'
                    }
                }
            }
            _ => {}
        }
    }
    prefixes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set<const N: usize>(items: [&str; N]) -> HashSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn assert_prefixes(expr: &str, expected: HashSet<String>) {
        assert_eq!(
            find_xpath_prefixes(expr),
            expected,
            "unexpected prefix set for: {expr}"
        );
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
    fn test_find_xpath_prefixes_skips_colons_inside_string_literals() {
        // Single-quoted identityref comparisons (RFC 7950 §9.10),
        // double-quoted variants, and mixed-quote expressions.
        let cases: &[(&str, HashSet<String>)] = &[
            ("../crypto = 'mc:aes'", HashSet::new()),
            ("name() = \"ns:bogus\"", HashSet::new()),
            ("@a:x = 'p:q' or @b:y = \"r:s\"", set(["a", "b"])),
        ];
        for (expr, expected) in cases {
            assert_prefixes(expr, expected.clone());
        }
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
        // ietf-interfaces-style `must`: only `if:` is a live prefix;
        // the `ianaift:*` tokens are identityref values inside string
        // literals and must not be reported.
        let must_expr = "(/if:interfaces/if:interface[if:name=current()]/if:type \
                         = 'ianaift:ethernetCsmacd') \
                         or \
                         (/if:interfaces/if:interface[if:name=current()]/if:type \
                         = 'ianaift:ieee8023adLag')";
        assert_prefixes(must_expr, set(["if"]));

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
}
