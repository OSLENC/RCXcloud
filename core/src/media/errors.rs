//! Media pipeline errors (fail-closed)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaError {
    InputTooLarge,
    UnsupportedFormat,
    DemuxFailed,
    DecodeFailed,
    SanitizationFailed,
