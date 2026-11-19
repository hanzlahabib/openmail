//! The single bound the MCP server needs from a backend: read + organize + drafts +
//! attachments + sent-folder copy. A blanket impl means an IMAP backend only has to implement
//! the individual `openmail-core` traits.
use openmail_core::backend::{
    AttachmentSource, MailBackend, MailDrafts, MailOrganizer, SentFolder,
};

pub trait FullBackend:
    MailBackend + MailOrganizer + MailDrafts + AttachmentSource + SentFolder
{
}

impl<T> FullBackend for T where
    T: MailBackend + MailOrganizer + MailDrafts + AttachmentSource + SentFolder
{
}
