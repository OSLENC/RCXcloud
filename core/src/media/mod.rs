//! Secure Media Pipeline (Phase 1.5)
// 🔒 API FREEZE:
// This module is frozen after Phase 1.5.
// Any change requires security review.

use crate::media::{
    container::demux,
    decode,
    errors::MediaError,
    format::MediaFormat,
    limits::check_media_size,
    output::{SanitizedAudio, SanitizedMedia, SanitizedVideo},
    sanitize,
    subtitles,
};

pub mod container;
pub mod decode;
pub mod errors;
pub mod format;
pub mod limits;
pub mod output;
pub mod sanitize;
pub mod subtitles;

/// 🔒 Single public media entry point
pub fn process_media(
    input: &[u8],
    format: MediaFormat,
) -> Result<SanitizedMedia, MediaError> {
    if !check_media_size(input.len()) {
        return Err(MediaError::InputTooLarge);
    }

    let streams = demux::demux(input)?;

    match format {
        MediaFormat::Audio => {
            let decoded = decode::audio::decode_audio(&streams.audio)?;
            let safe = sanitize::audio::sanitize_audio(decoded)?;

            Ok(SanitizedMedia::Audio(SanitizedAudio {
                pcm: safe.pcm,
                sample_rate: safe.sample_rate,
                channels: safe.channels,
            }))
        }

        MediaFormat::Video => {
    let decoded = decode::video::decode_video(&streams.video)?;
    let safe_core = sanitize::video::sanitize_video(decoded)?;

    let subtitles = match subtitles::decode::decode_subtitles(&streams.subtitles) {
        Ok(s) => s,
        Err(_) => Vec::new(),
    };

    Ok(SanitizedMedia::Video(SanitizedVideo {
        frames: safe_core.frames,
        width: safe_core.width,
        height: safe_core.height,
        subtitles,
    }))
}
    }
}

