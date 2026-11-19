//! The two pages a person sees: sign in + approve, and a plain error page. Everything
//! interpolated is escaped; client-supplied names are untrusted text.

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

const STYLE: &str = "body{font:16px system-ui,sans-serif;max-width:28rem;margin:4rem auto;padding:0 1rem;color:#111}\
input,button{font:inherit;padding:.5rem;margin:.25rem 0}input[type=password]{width:100%;box-sizing:border-box}\
button{cursor:pointer}.deny{background:none;border:1px solid #888}.err{color:#b00020}code{background:#eee;padding:0 .2rem}ul.scopes{list-style:none;padding:0}ul.scopes li{margin:.4rem 0}";

fn shell(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{}</title><style>{STYLE}</style></head><body>{body}</body></html>",
        escape(title)
    )
}

/// Plain-language meaning of the scopes OpenMail defines; unknown scopes show their raw name.
fn describe(scope: &str) -> &str {
    match scope {
        "mail:read" => "Read and search mail (read-only)",
        "mail:organize" => "Organize: mark read/unread, flag, move to archive",
        "mail:draft" => "Create and edit drafts (nothing is sent)",
        "mail:send" => "Send mail (each send still needs a separate approval from you)",
        "mail:delete" => "Delete",
        other => other,
    }
}

/// `offered` are every scope this server can grant; `checked` start ticked. The owner decides:
/// a client cannot widen access beyond what is ticked here. Account permissions in the server
/// config still apply on top of whatever is granted.
pub fn consent(
    tx: &str,
    client_name: &str,
    offered: &[String],
    checked: &[String],
    error: Option<&str>,
) -> String {
    let err = error.map_or(String::new(), |e| {
        format!("<p class=\"err\">{}</p>", escape(e))
    });
    let boxes: String = offered
        .iter()
        .map(|s| {
            let on = if checked.contains(s) { " checked" } else { "" };
            format!(
                "<li><label><input type=\"checkbox\" name=\"scope\" value=\"{v}\"{on}> {d} <code>{v}</code></label></li>",
                v = escape(s),
                d = escape(describe(s)),
            )
        })
        .collect();
    shell(
        "Authorize access to OpenMail",
        &format!(
            "<h1>Authorize access</h1><p><strong>{}</strong> wants to use your OpenMail server. Choose what it may do:</p>\
<form method=\"post\" action=\"/authorize\"><input type=\"hidden\" name=\"tx\" value=\"{}\"><ul class=\"scopes\">{boxes}</ul>\
<p>Only approve applications you started yourself. Sign in as the owner to continue.</p>{err}\
<label>Owner password<br><input type=\"password\" name=\"password\" autocomplete=\"current-password\" autofocus></label><br>\
<button type=\"submit\" name=\"decision\" value=\"allow\">Approve selected</button> \
<button type=\"submit\" name=\"decision\" value=\"allow_all\">Approve ALL permissions</button> \
<button type=\"submit\" name=\"decision\" value=\"deny\" class=\"deny\">Deny</button></form>",
            escape(client_name),
            escape(tx)
        ),
    )
}

pub fn error(message: &str) -> String {
    shell(
        "Authorization error",
        &format!(
            "<h1>Cannot continue</h1><p class=\"err\">{}</p><p>Close this window and start again from the application.</p>",
            escape(message)
        ),
    )
}
