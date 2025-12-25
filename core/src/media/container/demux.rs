use crate::media::errors::MediaError;
use crate::keystore::master::GLOBAL_KILLED;

use ffmpeg_next as ffmpeg;
use ffmpeg::media::Type;
use core::sync::atomic::Ordering;

const MAX_AUDIO_BYTES: usize = 64 * 1024 * 1024;
const MAX_VIDEO_BYTES: usize = 128 * 1024 * 1024;
const MAX_SUBTITLE_BYTES: usize = 4 * 1024 * 1024;

const MAX_AUDIO_PACKETS: usize = 100_000;
const MAX_VIDEO_PACKETS: usize = 200_000;
const MAX_SUBTITLE_PACKETS: usize = 50_000;

pub struct DemuxedStreams {
    pub audio: Vec<u8>,
    pub video: Vec<u8>,
    pub subtitles: Vec<u8>,
}

pub fn demux(input: &[u8]) -> Result<DemuxedStreams, MediaError> {
    if GLOBAL_KILLED.load(Ordering::SeqCst) {
        return Err(MediaError::DemuxFailed);
    }

    if input.is_empty() {
        return Err(MediaError::DemuxFailed);
    }

    ffmpeg::init().map_err(|_| MediaError::DemuxFailed)?;

    let mut cursor = std::io::Cursor::new(input);
    let mut ictx =
        ffmpeg::format::input(&mut cursor)
            .map_err(|_| MediaError::DemuxFailed)?;

    let mut audio = Vec::new();
    let mut video = Vec::new();
    let mut subtitles = Vec::new();

    let mut a_pk = 0usize;
    let mut v_pk = 0usize;
    let mut s_pk = 0usize;

    for (stream, packet) in ictx.packets() {
        if GLOBAL_KILLED.load(Ordering::SeqCst) {
            return Err(MediaError::DemuxFailed);
        }

        let data = packet.data();

        match stream.parameters().medium() {
            Type::Audio => {
                a_pk += 1;
                if a_pk > MAX_AUDIO_PACKETS || audio.len() + data.len() > MAX_AUDIO_BYTES {
                    return Err(MediaError::DemuxFailed);
                }
                audio.extend_from_slice(data);
            }
            Type::Video => {
                v_pk += 1;
                if v_pk > MAX_VIDEO_PACKETS || video.len() + data.len() > MAX_VIDEO_BYTES {
                    return Err(MediaError::DemuxFailed);
                }
                video.extend_from_slice(data);
            }
            Type::Subtitle => {
                s_pk += 1;
                if s_pk > MAX_SUBTITLE_PACKETS || subtitles.len() + data.len() > MAX_SUBTITLE_BYTES {
                    return Err(MediaError::DemuxFailed);
                }
                subtitles.extend_from_slice(data);
            }
            _ => {}
        }
    }

    if audio.is_empty() && video.is_empty() && subtitles.is_empty() {
        return Err(MediaError::DemuxFailed);
    }

    Ok(DemuxedStreams { audio, video, subtitles })
}
