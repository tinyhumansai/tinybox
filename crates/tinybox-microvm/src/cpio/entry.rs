//! What an initramfs is made of.

/// One thing in the guest's initial filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    /// The path inside the guest, without a leading slash.
    ///
    /// The kernel unpacks relative to `/`, and a leading slash produces an
    /// entry the guest cannot reach.
    pub(crate) path: String,
    /// What it is.
    pub(crate) kind: Kind,
}

/// The kinds of entry a tinybox initramfs needs.
///
/// Devices, links, and pipes are all expressible in `newc` and none are needed:
/// the guest gets `devtmpfs` for its device nodes and nothing else here has to
/// exist before `init` runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A directory.
    Directory,
    /// A regular file.
    File {
        /// Its contents.
        contents: Vec<u8>,
        /// Whether it should be runnable.
        executable: bool,
    },
}

impl Entry {
    /// A directory at `path`.
    pub(crate) fn directory(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            kind: Kind::Directory,
        }
    }

    /// A regular file at `path`.
    pub(crate) fn file(path: impl Into<String>, contents: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            kind: Kind::File {
                contents: contents.into(),
                executable: false,
            },
        }
    }

    /// A runnable file at `path`.
    pub(crate) fn program(path: impl Into<String>, contents: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            kind: Kind::File {
                contents: contents.into(),
                executable: true,
            },
        }
    }

    /// The bytes this entry contributes to the archive.
    pub(crate) fn body(&self) -> &[u8] {
        match &self.kind {
            Kind::Directory => &[],
            Kind::File { contents, .. } => contents,
        }
    }

    /// The `st_mode` value, combining the file type with its permissions.
    pub(crate) const fn mode(&self) -> u32 {
        match &self.kind {
            // `S_IFDIR` with rwxr-xr-x.
            Kind::Directory => 0o040_755,
            // `S_IFREG` with rwxr-xr-x or rw-r--r--.
            Kind::File { executable, .. } => {
                if *executable {
                    0o100_755
                } else {
                    0o100_644
                }
            }
        }
    }
}
