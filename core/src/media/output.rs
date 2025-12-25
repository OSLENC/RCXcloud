//! Sanitized media output (TRUST BOUNDARY)

use crate::media::subtitles::SubtitleCue;

/// Canonical PCM audio
pub struct SanitizedAudio {
    pub pcm: Vec<i16>,
    pub sample_rate: u32,
    pub channels: u8,
}

/// Canonical video output
pub struct SanitizedVideo {
    pub frames: Vec<Vec<u8>>, // RGBA
    pub width: u32,
    pub height: u32,
    pub subtitles: Vec<SubtitleCue>,
}
#[non_exhaustive]
pub enum SanitizedMedia {
    Audio(SanitizedAudio),
    Video(SanitizedVideo),
}
