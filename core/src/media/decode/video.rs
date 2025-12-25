use crate::media::errors::MediaError;
use crate::media::limits::{MAX_HEIGHT, MAX_VIDEO_FRAMES, MAX_WIDTH};
use crate::keystore::master::GLOBAL_KILLED;

use ffmpeg_next as ffmpeg;
use ffmpeg::{codec, format, frame, media, software::scaling};
use core::sync::atomic::Ordering;

pub(crate) struct DecodedVideo {
    pub frames: Vec<Vec<u8>>,
    pub width: u32,
    pub height: u32,
}

pub fn decode_video(input: &[u8]) -> Result<DecodedVideo, MediaError> {
    if GLOBAL_KILLED.load(Ordering::SeqCst) || input.is_empty() {
        return Err(MediaError::DecodeFailed);
    }

    ffmpeg::init().map_err(|_| MediaError::DecodeFailed)?;

    let mut cursor = std::io::Cursor::new(input);
    let mut ictx =
        format::input(&mut cursor)
            .map_err(|_| MediaError::DecodeFailed)?;

    let stream = ictx.streams()
        .best(media::Type::Video)
        .ok_or(MediaError::DecodeFailed)?;

    let ctx =
        codec::context::Context::from_parameters(stream.parameters())
            .map_err(|_| MediaError::DecodeFailed)?;

    let mut decoder =
        ctx.decoder().video()
            .map_err(|_| MediaError::DecodeFailed)?;

    let (w, h) = (decoder.width(), decoder.height());
    if w == 0 || h == 0 || w > MAX_WIDTH || h > MAX_HEIGHT {
        return Err(MediaError::DecodeFailed);
    }

    let mut scaler =
        scaling::Context::get(
            decoder.format(),
            w,
            h,
            ffmpeg::format::Pixel::RGBA,
            w,
            h,
            scaling::flag::Flags::BILINEAR,
        )
        .map_err(|_| MediaError::DecodeFailed)?;

    let mut frames = Vec::new();

    for (_, packet) in ictx.packets() {
        if GLOBAL_KILLED.load(Ordering::SeqCst) {
            return Err(MediaError::DecodeFailed);
        }

        decoder.send_packet(&packet).ok();

        let mut raw = frame::Video::empty();
        while decoder.receive_frame(&mut raw).is_ok() {
            if frames.len() >= MAX_VIDEO_FRAMES {
                return Err(MediaError::DecodeFailed);
            }

            let mut rgba = frame::Video::empty();
            scaler.run(&raw, &mut rgba)
                .map_err(|_| MediaError::DecodeFailed)?;

            frames.push(rgba.data(0).to_vec());
        }
    }

    decoder.send_eof().ok();

    Ok(DecodedVideo {
        frames,
        width: w,
        height: h,
    })
}
