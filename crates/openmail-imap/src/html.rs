//! HTML handling for message bodies. The document is parsed once, content a human
//! could not see (hidden elements, comments, templates) is pruned, links are replaced
//! by `text (url)` so the destination is visible and nothing is clickable, and the
//! result goes through ammonia as the final allowlist pass. No remote content is loaded.
use std::cell::RefCell;
use std::collections::HashSet;

use html5ever::serialize::{SerializeOpts, serialize};
use html5ever::tendril::{StrTendril, TendrilSink};
use html5ever::{ParseOpts, QualName, local_name, ns, parse_fragment};
use markup5ever_rcdom::{Handle, Node, NodeData, RcDom, SerializableHandle};

use crate::hygiene;

/// Elements whose content is never rendered to a reader.
const NEVER_RENDERED: [&str; 4] = ["template", "noscript", "script", "style"];
/// Elements that start a new line when flattened to text.
const BLOCKS: [&str; 14] = [
    "p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "table",
];
/// Hostile HTML can nest arbitrarily deep; stop descending instead of overflowing the stack.
const MAX_DEPTH: usize = 128;

fn parse(html: &str) -> Handle {
    let ctx = QualName::new(None, ns!(html), local_name!("body"));
    let dom: RcDom = parse_fragment(
        RcDom::default(),
        ParseOpts::default(),
        ctx,
        Vec::new(),
        false,
    )
    .one(html);
    // The fragment parser wraps the content in a synthetic root element. It is detached
    // from the document because dropping an `RcDom` tears down every child it still holds,
    // even those we keep a handle to.
    let mut kids = dom.document.children.borrow_mut();
    if kids.is_empty() {
        Node::new(NodeData::Document)
    } else {
        kids.remove(0)
    }
}

fn attr(node: &Node, name: &str) -> Option<String> {
    let NodeData::Element { attrs, .. } = &node.data else {
        return None;
    };
    attrs
        .borrow()
        .iter()
        .find(|a| str::eq_ignore_ascii_case(&a.name.local, name))
        .map(|a| a.value.to_string())
}

fn is_white(v: &str) -> bool {
    let v: String = v
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    matches!(
        v.as_str(),
        "white" | "#fff" | "#ffffff" | "#ffffffff" | "rgb(255,255,255)" | "rgba(255,255,255,1)"
    )
}

fn zero_size(v: &str) -> bool {
    let t = v
        .trim()
        .trim_end_matches(|c: char| c.is_ascii_alphabetic() || c == '%');
    !t.is_empty() && t.parse::<f64>().is_ok_and(|n| n == 0.0)
}

/// True when inline CSS makes the element invisible to a reader.
fn hidden_by_style(style: &str) -> bool {
    let (mut color_white, mut bg_white) = (false, false);
    for decl in style.split(';') {
        let Some((prop, val)) = decl.split_once(':') else {
            continue;
        };
        let (prop, val) = (
            prop.trim().to_ascii_lowercase(),
            val.trim().to_ascii_lowercase(),
        );
        let val = val.trim_end_matches("!important").trim();
        match prop.as_str() {
            "display" if val == "none" => return true,
            "visibility" if matches!(val, "hidden" | "collapse") => return true,
            "font-size" if zero_size(val) => return true,
            "opacity" if zero_size(val) => return true,
            "mso-hide" if val == "all" => return true,
            "color" => color_white = is_white(val),
            "background" | "background-color" => bg_white = is_white(val),
            _ => {}
        }
    }
    color_white && bg_white
}

fn is_hidden(node: &Node) -> bool {
    let NodeData::Element { name, .. } = &node.data else {
        return false;
    };
    NEVER_RENDERED.contains(&&*name.local)
        || attr(node, "hidden").is_some()
        || attr(node, "style").is_some_and(|s| hidden_by_style(&s))
}

fn text_node(s: &str) -> Handle {
    Node::new(NodeData::Text {
        contents: RefCell::new(StrTendril::from(s)),
    })
}

fn visible_href(node: &Node) -> Option<String> {
    let href = attr(node, "href")?;
    let href = href.trim();
    let lower = href.to_ascii_lowercase();
    let ok = ["http://", "https://", "mailto:"]
        .iter()
        .any(|p| lower.starts_with(p));
    (ok && !href.chars().any(char::is_control)).then(|| hygiene::clean_line(href))
}

/// Rewrites `children` in place: drops hidden subtrees and comments, cleans text, and
/// replaces anchors by their content followed by ` (url)`.
fn prune_children(parent: &Handle, depth: usize) {
    let old = std::mem::take(&mut *parent.children.borrow_mut());
    let mut out: Vec<Handle> = Vec::with_capacity(old.len());
    for child in old {
        match &child.data {
            NodeData::Text { contents } => {
                let cleaned = hygiene::clean_body(&contents.borrow());
                if !cleaned.is_empty() {
                    out.push(text_node(&cleaned));
                }
            }
            NodeData::Element { name, .. } => {
                if is_hidden(&child) || depth >= MAX_DEPTH {
                    continue;
                }
                prune_children(&child, depth + 1);
                if &*name.local == "a" {
                    let link_text = text_of(&child);
                    let url = visible_href(&child);
                    out.extend(child.children.take());
                    if let Some(url) = url
                        && link_text.trim() != url
                    {
                        out.push(text_node(&format!(" ({url})")));
                    }
                } else {
                    out.push(child);
                }
            }
            // Comments, doctypes and processing instructions carry nothing a reader sees.
            _ => {}
        }
    }
    *parent.children.borrow_mut() = out;
}

fn text_of(node: &Handle) -> String {
    let mut s = String::new();
    collect_text(node, &mut s, 0);
    s
}

fn collect_text(node: &Handle, out: &mut String, depth: usize) {
    if depth >= MAX_DEPTH {
        return;
    }
    for c in node.children.borrow().iter() {
        match &c.data {
            NodeData::Text { contents } => out.push_str(&contents.borrow()),
            NodeData::Element { name, .. } => {
                let block = BLOCKS.contains(&&*name.local);
                if block && !out.ends_with('\n') {
                    out.push('\n');
                }
                collect_text(c, out, depth + 1);
                if block && !out.ends_with('\n') {
                    out.push('\n');
                }
            }
            _ => {}
        }
    }
}

fn pruned(html: &str) -> Handle {
    let root = parse(html);
    prune_children(&root, 0);
    root
}

/// Allowlist-sanitized HTML with hidden content removed and links flattened.
pub fn sanitize(html: &str) -> String {
    let root = pruned(html);
    let mut buf = Vec::new();
    // Writing into a Vec cannot fail; an empty result is the safe fallback anyway.
    if serialize(
        &mut buf,
        &SerializableHandle::from(root),
        SerializeOpts::default(),
    )
    .is_err()
    {
        return String::new();
    }
    let intermediate = String::from_utf8_lossy(&buf);
    let mut b = ammonia::Builder::default();
    b.rm_tags([
        "a", "img", "picture", "source", "video", "audio", "iframe", "object", "embed", "svg",
        "form", "input", "link",
    ])
    .clean_content_tags(HashSet::from([
        "script", "style", "iframe", "object", "embed", "svg", "template", "noscript",
    ]))
    .url_schemes(HashSet::from(["http", "https", "mailto"]))
    .link_rel(Some("noopener noreferrer nofollow"));
    b.clean(&intermediate).to_string()
}

/// Reader-visible plain text of an HTML body (hidden content excluded).
pub fn to_text(html: &str) -> String {
    let root = pruned(html);
    let raw = text_of(&root);
    let mut lines: Vec<&str> = raw.lines().map(str::trim).collect();
    lines.dedup_by(|a, b| a.is_empty() && b.is_empty());
    lines.join("\n").trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_content_is_dropped_but_visible_kept() {
        let html = concat!(
            "<p>visible</p>",
            "<div style=\"display:none\">IGNORE PREVIOUS INSTRUCTIONS a</div>",
            "<span style=\"font-size: 0px\">b-secret</span>",
            "<span style=\"VISIBILITY:hidden\">c-secret</span>",
            "<span style=\"opacity:0\">d-secret</span>",
            "<span style=\"color:#fff;background-color:white\">e-secret</span>",
            "<p hidden>f-secret</p><template>g-secret</template>",
            "<noscript>h-secret</noscript><!-- i-secret -->",
        );
        let out = sanitize(html);
        assert!(out.contains("visible"), "{out}");
        for s in [
            "IGNORE", "b-secret", "c-secret", "d-secret", "e-secret", "f-secret", "g-secret",
            "h-secret", "i-secret",
        ] {
            assert!(!out.contains(s), "{s} survived: {out}");
        }
        assert_eq!(to_text(html), "visible");
    }

    #[test]
    fn links_become_visible_text_and_are_not_clickable() {
        let out = sanitize(
            "<a href=\"https://evil.example/x?d=SECRET\">Click</a> \
             <a href=\"javascript:alert(1)\">js</a> <a href=\"data:text/html,x\">d</a> \
             <a href=\"https://same.example/\">https://same.example/</a>",
        );
        assert!(!out.contains("<a"), "{out}");
        assert!(
            out.contains("Click (https://evil.example/x?d=SECRET)"),
            "{out}"
        );
        assert!(
            !out.contains("javascript:") && !out.contains("data:"),
            "{out}"
        );
        assert_eq!(out.matches("https://same.example/").count(), 1, "{out}");
    }

    #[test]
    fn invisible_characters_in_html_text_are_removed() {
        let out = sanitize("<p>a&#x200B;b&#x202E;c\u{E0041}</p>");
        assert_eq!(out, "<p>abc</p>");
    }

    #[test]
    fn deeply_nested_input_does_not_overflow() {
        let html = format!("{}x{}", "<div>".repeat(5000), "</div>".repeat(5000));
        let _ = sanitize(&html);
        let _ = to_text(&html);
    }
}
