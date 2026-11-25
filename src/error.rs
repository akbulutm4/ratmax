use std::{fmt, io, path::PathBuf};

#[derive(Debug)]
pub enum Error {
    UnsupportedModel(u16),
    InvalidCore(String),
    Manifest(String),
    File {
        path: PathBuf,
        source: io::Error,
    },
    NotRegularFile(PathBuf),
    Length {
        context: &'static str,
        expected: usize,
        actual: u64,
    },
    Address {
        record: usize,
        expected: u32,
        actual: u32,
    },
    Hash {
        context: &'static str,
        expected: String,
        actual: String,
    },
    BufferHeader,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedModel(id) => {
                write!(f, "unsupported model 0x{id:03X}; expected W95 Max 0x578")
            }
            Self::InvalidCore(value) => write!(f, "invalid Core {value:?}; expected 1, 2, 3 or 4"),
            Self::Manifest(message) => write!(f, "invalid embedded asset manifest: {message}"),
            Self::File { path, source } => write!(f, "{}: {source}", path.display()),
            Self::NotRegularFile(path) => write!(
                f,
                "{} is not a regular file (symlinks are excluded)",
                path.display()
            ),
            Self::Length {
                context,
                expected,
                actual,
            } => write!(f, "{context}: expected {expected} bytes, found {actual}"),
            Self::Address {
                record,
                expected,
                actual,
            } => write!(
                f,
                "record {record}: expected encoded address 0x{expected:08X}, found 0x{actual:08X}"
            ),
            Self::Hash {
                context,
                expected,
                actual,
            } => write!(
                f,
                "{context} SHA-256 mismatch: expected {expected}, found {actual}"
            ),
            Self::BufferHeader => write!(
                f,
                "invalid local record-buffer header; expected report ID 07 and the checkpoint 15 layout"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::File { source, .. } => Some(source),
            _ => None,
        }
    }
}
