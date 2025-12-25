//! Subtitle decoding (best-effort, text only)

use crate::media::errors::MediaError;
use super::SubtitleCue;

/// Decode subtitles from hostile media input.
///
/// SECURITY:
/// - Text-only subtitles
/// - Best-effort (failure is NON-fatal)
/// - No panics
/// - No logging
/// - No filesystem access
///
/// NOTE:
/// ffmpeg-next integration will be implemented here.
/// This stub is intentionally safe and minimal.
pub fn decode_subtitles(
    _input: &[u8],
) -> Result<Vec<SubtitleCue>, MediaError> {
    // ffmpeg-next subtitle decoding goes here
    // Any failure should return MediaError::DecodeFailed
    Ok(Vec::new())
}
