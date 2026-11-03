//! Node announcements, kept in memory (docs/DIRECTORY_PROTOCOL.md "Node
//! announcements").
//!
//! Announcements are requests to be listed, not directory data: the relay
//! keeps the newest unexpired one per provider and forgets them on restart.
//! Operators republish daily, and the publisher reads them from here.

use std::collections::BTreeMap;

use crate::wire::ValidatedAnnouncement;

/// Most announcements held at once; a new provider beyond it is refused.
pub const MAX_ANNOUNCEMENTS: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnnounceDisposition {
    Saved,
    Duplicate,
    ReplacedByNewer,
    CapacityExceeded,
}

#[derive(Default)]
pub struct AnnouncementBoard {
    by_provider: BTreeMap<[u8; 32], ValidatedAnnouncement>,
}

impl AnnouncementBoard {
    pub fn offer(&mut self, announcement: ValidatedAnnouncement, now: u64) -> AnnounceDisposition {
        self.prune(now);
        match self.by_provider.get(&announcement.provider_id) {
            Some(held) if held.event_id == announcement.event_id => AnnounceDisposition::Duplicate,
            // NIP-01 replacement: a later created_at wins, then the lower id.
            Some(held)
                if (held.created_at, std::cmp::Reverse(held.event_id))
                    > (
                        announcement.created_at,
                        std::cmp::Reverse(announcement.event_id),
                    ) =>
            {
                AnnounceDisposition::ReplacedByNewer
            }
            None if self.by_provider.len() >= MAX_ANNOUNCEMENTS => {
                AnnounceDisposition::CapacityExceeded
            }
            _ => {
                self.by_provider
                    .insert(announcement.provider_id, announcement);
                AnnounceDisposition::Saved
            }
        }
    }

    /// Every unexpired announcement's event JSON, in provider id order.
    pub fn current(&mut self, now: u64) -> Vec<Vec<u8>> {
        self.prune(now);
        self.by_provider
            .values()
            .map(|announcement| announcement.canonical_json.clone())
            .collect()
    }

    fn prune(&mut self, now: u64) {
        self.by_provider
            .retain(|_, announcement| announcement.expiration >= now);
    }
}
