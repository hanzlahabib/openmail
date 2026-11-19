# Yahoo Mail

Checked 2026-11-19 against Yahoo's help page <https://help.yahoo.com/kb/SLN3697.html> (snippet seen in search
results, page not read in full). Hosts/ports verified from that snippet; the app-password requirement comes from
third-party pages (UNVERIFIED), which disagree on whether the normal password still works.

| | Host | Port | TLS |
|---|---|---|---|
| IMAP | `imap.mail.yahoo.com` | 993 | SSL, auth required |
| SMTP | `smtp.mail.yahoo.com` | 465 or 587 | SSL; auth required |

Auth: generate an app password in Account Security ("Generate app password" under "Other ways to sign in").
Use it, not the account password.
