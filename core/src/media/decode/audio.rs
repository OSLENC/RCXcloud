use crate::media::errors::MediaError;
use crate::media::limits::MAX_AUDIO_SAMPLES;
use crate::keystore::master::GLOBAL_KILLED;

use ffmpeg_next as ffmpeg;
use ffmpeg::{codec, format, frame, media};
use core::sync::atomic::Ordering;

pub(crate) struct DecodedAudio {
    pub pcm: Vec<i16>,
    pub sample_rate: u32,
    pub channels: u8,
}

pub fn decode_audio(input: &[u8]) -> Result<DecodedAudio, MediaError> {
    if GLOBAL_KILLED.load(Ordering::SeqCst) || input.is_empty() {
        return Err(MediaError::DecodeFailed);
    }

    ffmpeg::init().map_err(|_| MediaError::DecodeFailed)?;

    let mut cursor = std::io::Cursor::new(input);
    let mut ictx =
        format::input(&mut cursor)
            .map_err(|_| MediaError::DecodeFailed)?;

    let stream = ictx.streams()
        .best(media::Type::Audio)
        .ok_or(MediaError::DecodeFailed)?;

    let ctx =
        codec::context::Context::from_parameters(stream.parameters())
            .map_err(|_| MediaError::DecodeFailed)?;

    let mut decoder =
        ctx.decoder().audio()
            .map_err(|_| MediaError::DecodeFailed)?;

    let mut pcm = Vec::<i16>::new();

    for (_, packet) in ictx.packets() {
        if GLOBAL_KILLED.load(Ordering::SeqCst) {
            return Err(MediaError::DecodeFailed);
        }

        decoder.send_packet(&packet).ok();

        let mut frame = frame::Audio::empty();
        while decoder.receive_frame(&mut frame).is_ok() {
            let data = frame.data(0);

            if data.len() % 2 != 0 {
                return Err(MediaError::DecodeFailed);
            }

            for chunk in data.chunks_exact(2) {
                if pcm.len() >= MAX_AUDIO_SAMPLES {
                    return Err(MediaError::DecodeFailed);
                }
                pcm.push(i16::from_le_bytes([chunk[0], chunk[1]]));
            }
        }
    }

    decoder.send_eof().ok();

    let rate = decoder.rate();
    let channels = decoder.channels();

    if rate == 0 || channels == 0 {
        return Err(MediaError::DecodeFailed);
    }

    Ok(DecodedAudio {
        pcm,
        sample_rate: rate,
        channels: channels as u8,
    })
}
