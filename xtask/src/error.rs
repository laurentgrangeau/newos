//! Structured error type for `xtask` build, packaging, and verification workflows.

use std::fmt;
use std::process::ExitStatus;

/// Unified error type returned across `xtask` library and CLI operations.
#[derive(Debug)]
pub enum XtaskError {
    /// Filesystem or OS I/O failure with operation context.
    Io {
        context: String,
        source: std::io::Error,
    },
    /// External subprocess exited with a non-zero status.
    CommandFailed { label: String, status: ExitStatus },
    /// Non-UTF-8 path where a UTF-8 CLI argument is required.
    InvalidPath { label: &'static str },
    /// Invalid CLI subcommand, flag, or argument value.
    Cli(String),
    /// TOML profile syntax, duplicate key, or value parse error.
    ProfileParse { line: usize, message: String },
    /// Profile dependency or target validation error.
    ProfileValidation(String),
    /// GPT / FAT32 ESP geometry or image assembly error.
    Gpt(String),
    /// ELF64 binary security audit failure (header, PIE, W^X, soft-float).
    ElfAudit { binary: String, reason: String },
    /// QEMU firmware discovery, execution, timeout, or guest self-test failure.
    Qemu(String),
    /// Benchmark or reproducible-build verification failure.
    Verification(String),
}

impl XtaskError {
    /// Construct an I/O error with human-readable operation context.
    #[must_use]
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

impl fmt::Display for XtaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { context, source } => write!(f, "{context}: {source}"),
            Self::CommandFailed { label, status } => {
                write!(f, "{label} exited with status {status}")
            }
            Self::InvalidPath { label } => write!(f, "invalid {label} path (non-UTF-8)"),
            Self::Cli(msg)
            | Self::ProfileValidation(msg)
            | Self::Gpt(msg)
            | Self::Qemu(msg)
            | Self::Verification(msg) => f.write_str(msg),
            Self::ProfileParse { line, message } => write!(f, "line {line}: {message}"),
            Self::ElfAudit { binary, reason } => write!(f, "{binary}: {reason}"),
        }
    }
}

impl std::error::Error for XtaskError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<std::io::Error> for XtaskError {
    fn from(source: std::io::Error) -> Self {
        Self::Io {
            context: "I/O error".to_string(),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn io_error_preserves_source_and_context() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing file");
        let err = XtaskError::io("read profile", io_err);
        assert!(err.source().is_some());
        assert!(err.to_string().contains("read profile"));
        assert!(err.to_string().contains("missing file"));
    }

    #[test]
    fn non_io_variants_format_cleanly_and_have_no_source() {
        let cases = [
            (
                XtaskError::InvalidPath { label: "disk" },
                "invalid disk path (non-UTF-8)",
            ),
            (XtaskError::Cli("bad flag".into()), "bad flag"),
            (
                XtaskError::ProfileParse {
                    line: 7,
                    message: "expected boolean".into(),
                },
                "line 7: expected boolean",
            ),
            (
                XtaskError::ProfileValidation("missing sha3".into()),
                "missing sha3",
            ),
            (XtaskError::Gpt("too small".into()), "too small"),
            (
                XtaskError::ElfAudit {
                    binary: "newos-kernel".into(),
                    reason: "W^X violation".into(),
                },
                "newos-kernel: W^X violation",
            ),
            (XtaskError::Qemu("timed out".into()), "timed out"),
            (XtaskError::Verification("mismatch".into()), "mismatch"),
        ];
        for (err, expected) in cases {
            assert!(err.source().is_none());
            assert_eq!(err.to_string(), expected);
        }
    }

    #[test]
    fn from_io_error_wraps_with_source() {
        let err = XtaskError::from(std::io::Error::other("boom"));
        assert!(err.source().is_some());
        assert!(err.to_string().contains("boom"));
    }
}
