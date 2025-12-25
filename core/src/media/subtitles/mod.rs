//! Subtitle decoding (text only)

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubtitleCue {
    pub start_ms: u64,
    pub end_ms: u64,
    pub text: String,
}

pub mod decode;
