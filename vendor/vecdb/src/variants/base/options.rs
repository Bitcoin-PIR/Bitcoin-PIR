use rawdb::Database;

use crate::Version;

/// Options for importing or creating stored vectors.
#[derive(Clone, Copy)]
pub struct ImportOptions<'a> {
    /// Database to store the vector in.
    pub db: &'a Database,
    /// Name of the vector.
    pub name: &'a str,
    /// Version for tracking data schema compatibility.
    pub version: Version,
    /// Number of stamped change files to keep for rollback support (0 to disable).
    pub saved_stamped_changes: u16,
}

impl<'a> ImportOptions<'a> {
    pub fn new(db: &'a Database, name: &'a str, version: Version) -> Self {
        Self {
            db,
            name,
            version,
            saved_stamped_changes: 0,
        }
    }

    pub fn with_saved_stamped_changes(mut self, num: u16) -> Self {
        self.saved_stamped_changes = num;
        self
    }
}

impl<'a> From<(&'a Database, &'a str, Version)> for ImportOptions<'a> {
    fn from((db, name, version): (&'a Database, &'a str, Version)) -> Self {
        Self::new(db, name, version)
    }
}
