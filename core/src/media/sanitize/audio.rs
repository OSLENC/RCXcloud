
//! Audio sanitization (canonicalization)

use crate::media::decode::audio::DecodedAudio;
use crate::media::errors::MediaError;

pub(crate) fn sanitize_audio(
    decoded: DecodedAudio,
) -> Result<DecodedAudio, MediaError> {
    if decoded.sample_rate == 0 {
        return Err(MediaError::SanitizationFailed);
    }
    if decoded.channels == 0 {
        return Err(MediaError::SanitizationFailed);
    }

    Ok(decoded)
}

