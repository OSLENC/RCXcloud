
//! Media resource limits (DoS protection)

/// Max encrypted input size (256 MiB)
pub const MAX_MEDIA_BYTES: usize = 256 * 1024 * 1024;

/// Max decoded video frames
pub const MAX_VIDEO_FRAMES: usize = 2_000;

/// Max video resolution
pub const MAX_WIDTH: u32 = 4096;
pub const MAX_HEIGHT: u32 = 4096;

/// Max audio samples per track
pub const MAX_AUDIO_SAMPLES: usize = 10 * 60 * 48_000; // 10 min @ 48kHz

#[inline(always)]
pub fn check_media_size(len: usize) -> bool {
    len <= MAX_MEDIA_BYTES
}

