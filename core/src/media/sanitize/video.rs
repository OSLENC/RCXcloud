//! Video sanitization (canonical frames)

use crate::media::decode::video::DecodedVideo;
use crate::media::errors::MediaError;

/// Internal sanitized video core (NO subtitles)
pub(crate) struct SafeVideoCore {
    pub frames: Vec<Vec<u8>>,
    pub width: u32,
    pub height: u32,
}

pub(crate) fn sanitize_video(
    decoded: DecodedVideo,
) -> Result<SafeVideoCore, MediaError> {
    if decoded.width == 0 || decoded.height == 0 {
        return Err(MediaError::SanitizationFailed);
    }

    Ok(SafeVideoCore {
        frames: decoded.frames,
        width: decoded.width,
        height: decoded.height,
    })
}

