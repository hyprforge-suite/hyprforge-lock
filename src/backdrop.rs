//! The wallpaper, prepared once per output instead of every frame.
//!
//! Drawn from its path, a 3840×2160 wallpaper is resampled onto the
//! output on every repaint. Measured in a nested compositor at 1440×900
//! physical: 45ms a frame with the wallpaper, 20ms without — so more than
//! half of every frame was the same resize, done again. That is a shake
//! that stutters, and a locked laptop spending a slice of a core each
//! second redrawing a picture that has not changed.
//!
//! So the lock asks for the wallpaper at each output's exact physical
//! size, already cropped to cover it and already dimmed, and draws that
//! one-to-one. The work happens on a thread of its own: the first frames
//! draw from the path as before, because a session lock waits for them
//! and nothing here is worth keeping a session open for.
//!
//! Decoding goes through `hyprforge-image`'s budget, never a bare
//! `image::open`. This is the process where a 36-megapixel wallpaper once
//! peaked at 296MB, and an allocation failure on a lock screen is not
//! recoverable.

use calloop::ping::Ping;
use hyprforge_look::Color;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};

/// A request: this wallpaper, for an output this many physical pixels.
struct Request {
    path: PathBuf,
    width: u32,
    height: u32,
    dim: f32,
    tint: Color,
}

/// A prepared backdrop.
pub struct Prepared {
    pub width: u32,
    pub height: u32,
    pub handle: iced_runtime::core::image::Handle,
}

pub struct Backdrops {
    requests: Sender<Request>,
    ready: Receiver<Prepared>,
}

impl Backdrops {
    pub fn start() -> (Backdrops, calloop::ping::PingSource) {
        let (requests, incoming) = std::sync::mpsc::channel::<Request>();
        let (done, ready) = std::sync::mpsc::channel();
        let (ping, source) = calloop::ping::make_ping().expect("failed to create a wakeup pipe");
        // A thread that cannot start leaves the lock drawing from the
        // path, which is slower and exactly as correct.
        let _ = std::thread::Builder::new()
            .name("backdrop".into())
            .spawn(move || run(incoming, done, ping));
        (Backdrops { requests, ready }, source)
    }

    pub fn request(&self, path: PathBuf, (width, height): (u32, u32), dim: f32, tint: Color) {
        let _ = self.requests.send(Request { path, width, height, dim, tint });
    }

    pub fn poll(&self) -> Option<Prepared> {
        self.ready.try_recv().ok()
    }
}

fn run(requests: Receiver<Request>, done: Sender<Prepared>, ping: Ping) {
    while let Ok(request) = requests.recv() {
        match prepare(&request) {
            Ok(prepared) => {
                if done.send(prepared).is_err() {
                    return;
                }
                ping.ping();
            }
            // Only the reason; a wallpaper path is not a secret but the
            // drawing falls back to it, so there is nothing more to say.
            Err(why) => eprintln!("backdrop: drawing the wallpaper directly instead ({why})"),
        }
    }
}

fn prepare(request: &Request) -> Result<Prepared, String> {
    let (width, height) = (request.width.max(1), request.height.max(1));
    let measured = hyprforge_image::measure(&request.path).map_err(|e| e.to_string())?;
    let source = measured.source;
    // Decoded no larger than covering needs: the source scaled so its
    // shorter side (relative to the output's shape) meets the output's.
    let cover = cover_scale((source.width, source.height), (width, height));
    let edge = ((source.width.max(source.height) as f64) * cover.min(1.0)).ceil() as u32;
    let decoded = hyprforge_image::decode_to_fit(&request.path, &hyprforge_image::Budget::for_edge(edge.max(1)))
        .map_err(|e| e.to_string())?;
    let image = image::RgbaImage::from_raw(decoded.size.width, decoded.size.height, decoded.pixels)
        .ok_or("the decoder's buffer was the wrong size")?;

    let (scaled_w, scaled_h, x, y) = cover_crop((image.width(), image.height()), (width, height));
    let scaled = image::imageops::resize(&image, scaled_w, scaled_h, image::imageops::FilterType::Triangle);
    drop(image);
    let mut cropped = image::imageops::crop_imm(&scaled, x, y, width, height).to_image();
    drop(scaled);
    dim(&mut cropped, request.tint, request.dim);

    Ok(Prepared {
        width,
        height,
        handle: iced_runtime::core::image::Handle::from_rgba(width, height, cropped.into_raw()),
    })
}

/// How much `source` must be scaled to cover `target` — the larger of the
/// two axis ratios, which is what CSS's `cover` and iced's `ContentFit::Cover`
/// both mean.
fn cover_scale((sw, sh): (u32, u32), (tw, th): (u32, u32)) -> f64 {
    let (sw, sh) = (f64::from(sw.max(1)), f64::from(sh.max(1)));
    (f64::from(tw) / sw).max(f64::from(th) / sh)
}

/// The size to scale `source` to so it covers `target`, and the offset of
/// the centred crop: `(width, height, x, y)`. The scaled size never falls
/// short of the target by rounding, which would leave a one-pixel seam.
fn cover_crop(source: (u32, u32), (tw, th): (u32, u32)) -> (u32, u32, u32, u32) {
    let scale = cover_scale(source, (tw, th));
    let w = ((f64::from(source.0.max(1)) * scale).round() as u32).max(tw);
    let h = ((f64::from(source.1.max(1)) * scale).round() as u32).max(th);
    (w, h, (w - tw) / 2, (h - th) / 2)
}

/// The theme's dim, baked in: the same `background` at `dim` opacity the
/// screen would otherwise lay over the picture every frame.
fn dim(image: &mut image::RgbaImage, tint: Color, amount: f32) {
    let a = amount.clamp(0.0, 1.0) * f32::from(tint.a) / 255.0;
    if a <= 0.0 {
        return;
    }
    let (r, g, b) = (f32::from(tint.r), f32::from(tint.g), f32::from(tint.b));
    for pixel in image.pixels_mut() {
        let [pr, pg, pb, _] = pixel.0;
        pixel.0[0] = (f32::from(pr) * (1.0 - a) + r * a).round() as u8;
        pixel.0[1] = (f32::from(pg) * (1.0 - a) + g * a).round() as u8;
        pixel.0[2] = (f32::from(pb) * (1.0 - a) + b * a).round() as u8;
        // Opaque: a lock screen shows nothing through itself.
        pixel.0[3] = 255;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wider_picture_is_cropped_at_the_sides_and_a_taller_one_top_and_bottom() {
        // 16:9 onto 16:10: height governs, the sides are cropped.
        assert_eq!(cover_crop((3840, 2160), (2560, 1600)), (2844, 1600, 142, 0));
        // Portrait output: width governs.
        assert_eq!(cover_crop((3840, 2160), (900, 1600)), (2844, 1600, 972, 0));
        // Taller picture onto a wide output.
        assert_eq!(cover_crop((1000, 2000), (1440, 900)), (1440, 2880, 0, 990));
    }

    /// Rounding must never leave the scaled picture a pixel short of the
    /// output, or the crop would read past its edge.
    #[test]
    fn the_scaled_picture_always_covers_the_output() {
        for source in [(3840, 2160), (1, 1), (7, 3), (1920, 1080), (4000, 3000)] {
            for target in [(2560, 1600), (864, 540), (1, 1), (1441, 899), (900, 1600)] {
                let (w, h, x, y) = cover_crop(source, target);
                assert!(w >= target.0 && h >= target.1, "{source:?} → {target:?}");
                assert!(x + target.0 <= w && y + target.1 <= h, "{source:?} → {target:?}");
            }
        }
    }

    #[test]
    fn the_baked_dim_matches_the_overlay_it_replaces_and_is_opaque() {
        let mut image = image::RgbaImage::from_pixel(1, 1, image::Rgba([200, 100, 0, 255]));
        dim(&mut image, Color::rgba(0, 0, 0, 255), 0.5);
        assert_eq!(image.get_pixel(0, 0).0, [100, 50, 0, 255]);
        let mut untouched = image::RgbaImage::from_pixel(1, 1, image::Rgba([1, 2, 3, 255]));
        dim(&mut untouched, Color::rgba(0, 0, 0, 255), 0.0);
        assert_eq!(untouched.get_pixel(0, 0).0, [1, 2, 3, 255]);
    }

    /// Test the resource, not just the result: what one prepared backdrop
    /// costs to keep is the output's own buffer size, not the wallpaper's.
    #[test]
    fn a_prepared_backdrop_is_the_size_of_the_output_not_the_wallpaper() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wall.png");
        image::RgbaImage::from_pixel(1600, 900, image::Rgba([10, 20, 30, 255])).save(&path).unwrap();
        let prepared = prepare(&Request {
            path,
            width: 320,
            height: 200,
            dim: 0.35,
            tint: Color::rgba(0, 0, 0, 255),
        })
        .unwrap();
        assert_eq!((prepared.width, prepared.height), (320, 200));
        match prepared.handle {
            iced_runtime::core::image::Handle::Rgba { width, height, pixels, .. } => {
                assert_eq!((width, height), (320, 200));
                assert_eq!(pixels.len(), 320 * 200 * 4);
            }
            _ => panic!("expected an in-memory handle"),
        }
    }
}
