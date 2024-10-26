use std::{error::Error, time::Duration};

use bytesize::ByteSize;
use log::debug;
use regex::Regex;
use scopeguard::defer;

pub fn to_invisible(input: u128) -> String {
	// 0xE2 80 8[B-F] are invisible, we are able to encode at an efficiency of 1 byte per 12 bytes
	// 4 states per chunk, 2^2, 2 bits
	let mut arr: Vec<u8> = vec![];
	arr.reserve(16 * 12);

	input.to_le_bytes().iter().for_each(|x| {
		let one = x & 0b00000011;
		let two = (x & 0b00001100) >> 2;
		let three = (x & 0b00110000) >> 4;
		let four = (x & 0b11000000) >> 6;

		arr.extend_from_slice(&[
			0xE2,
			0x80,
			0x8B + one,
			0xE2,
			0x80,
			0x8B + two,
			0xE2,
			0x80,
			0x8B + three,
			0xE2,
			0x80,
			0x8B + four,
		]);
	});

	unsafe { String::from_utf8_unchecked(arr) }
}

pub fn from_invisible(input: String) -> Result<u128, Box<dyn Error>> {
	let bytes = input.as_bytes();

	if bytes.len() % 12 != 0 || bytes.chunks_exact(3).any(|x| !(0x8B..0x8F).contains(&x[2])) {
		return Err("invalid bytes".into());
	}

	let chunks = bytes.chunks_exact(12);

	let bytes: Vec<u8> = chunks
		.into_iter()
		.map(|x| {
			let one = x[2] - 0x8B;
			let two = x[5] - 0x8B;
			let three = x[8] - 0x8B;
			let four = x[11] - 0x8B;

			(four << 6) + (three << 4) + (two << 2) + one
		})
		.collect();

	let slice = bytes.try_into().map_err(|x| format!("{x:?}"))?;

	Ok(u128::from_le_bytes(slice))
}

#[test]
fn test_invisible() {
	let data = 0xFFFF_FFFF_FFFF_FFFF;

	let encoded_data = to_invisible(data);

	assert_eq!(data, from_invisible(encoded_data).unwrap());
}

pub fn data_hash(bytes: &[u8]) -> (u128, String) {
	let hash = meowhash::MeowHasher::hash(bytes).as_u128();

	(hash, radix_fmt::radix_36(hash).to_string())
}

pub fn generate_token() -> String {
	// generate a unique 128-char token identifier.

	random_string::generate(
		128,
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	)
}

pub fn generate_invite() -> String {
	// generate a unique identifier.
	let charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

	format!(
		"{}-{}-{}-{}-{}",
		random_string::generate(5, charset),
		random_string::generate(5, charset),
		random_string::generate(5, charset),
		random_string::generate(5, charset),
		random_string::generate(5, charset)
	)
}

pub enum MediaType {
	Image,
	Video,
}

#[derive(Debug)]
struct MediaInfo {
	fps: f64,
	len: Duration,
	resolution: (u64, u64),
	bitrates: (u64, u64),
}

impl MediaInfo {
	async fn new(path: &str) -> Result<Self, Box<dyn Error>> {
		let ffprobe = {
			let out = async_process::Command::new("ffprobe")
				.args(["-i", path])
				.output()
				.await?;

			String::from_utf8_lossy(&out.stderr).into_owned()
		};

		let ffprobe = ffprobe.as_str();

		// debug!("{ffprobe}");

		// fix the fps regex to support flat numbers
		let bit_regex = Regex::new("bit_rate=(\\d*)")?;
		let dur_regex = Regex::new("Duration: (\\d*?):(\\d\\d):(\\d\\d).(\\d\\d)[^,]*")?;
		let fps_regex = Regex::new(", ([\\d.]*?) fps, ")?;
		let res_regex = Regex::new(", (\\d*)x(\\d*)")?;

		// get the bitrates
		let vid_bitrate: u64 = {
			let out = async_process::Command::new("ffprobe")
				.args([
					"-i",
					path,
					"-select_streams",
					"v:0",
					"-show_entries",
					"stream=bit_rate",
					"-v",
					"0",
				])
				.output()
				.await?;

			let out = String::from_utf8_lossy(&out.stdout).into_owned();

			// debug!("{out}");

			if let Some(x) = bit_regex.captures(out.as_str()) {
				x[1].parse()?
			} else {
				return Err("could not identify bitrate".into());
			}
		};

		let aud_bitrate: u64 = {
			let out = async_process::Command::new("ffprobe")
				.args([
					"-i",
					path,
					"-select_streams",
					"a:0",
					"-show_entries",
					"stream=bit_rate",
					"-v",
					"0",
				])
				.output()
				.await?;

			let out = String::from_utf8_lossy(&out.stdout).into_owned();

			// debug!("{out}");

			if let Some(x) = bit_regex.captures(out.as_str()) {
				x[1].parse()?
			} else {
				return Err("could not identify bitrate".into());
			}
		};

		let bitrates = (vid_bitrate, aud_bitrate);

		// duration is in format HH:MM:SS.MS 00:00:48.98
		let duration: (u64, u64, u64, u64) = if let Some(x) = dur_regex.captures(ffprobe) {
			(x[1].parse()?, x[2].parse()?, x[3].parse()?, x[4].parse()?)
		} else {
			return Err("could not identify duration".into());
		};

		let len: Duration = Duration::from_millis(duration.3)
			+ Duration::from_secs(duration.2 + duration.1 * 60 + duration.0 * 60 * 60);

		// there may be multiple matches, but we only need the first one,
		// as we only process the first video stream.
		let fps: f64 = if let Some(x) = fps_regex.captures(ffprobe) {
			x[1].parse()?
		} else {
			return Err("could not identify framerate".into());
		};

		let resolution: (u64, u64) = if let Some(x) = res_regex.captures(ffprobe) {
			(x[1].parse()?, x[2].parse()?)
		} else {
			return Err("could not identify resolution".into());
		};

		Ok(Self {
			fps,
			len,
			resolution,
			bitrates,
		})
	}
}

pub async fn encode_media(
	media_type: MediaType,
	hash: String,
	blob: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
	match media_type {
		MediaType::Image => {
			// imagemagick bs
			// write file to temporary folder
			let file_path = format!("{}/input", &hash);
			let out_path = format!("{}/output.webp", &hash);
			tokio::fs::create_dir(&hash).await?;
			tokio::fs::write(&file_path, blob).await?;

			defer! {
				// delete files
				let _ = std::fs::remove_dir_all(&hash);
			}

			let bytesize = format!("{}", ByteSize::mib(18).as_u64());

			let args = [
				file_path.as_str(),
				"-size",
				bytesize.as_str(),
				"-o",
				out_path.as_str(),
			];

			let _output = async_process::Command::new("cwebp")
				.args(args)
				.output()
				.await?;

			// read file out
			let file_blob = tokio::fs::read(out_path).await?;

			assert!(file_blob.len() < ByteSize::mib(20).as_u64() as usize);

			debug!(
				"Result: {} bytes -> {} bytes ({:.3}%)",
				blob.len(),
				file_blob.len(),
				(file_blob.len() / blob.len()) * 100
			);

			if !file_blob.is_empty() {
				Ok(file_blob)
			} else {
				Err("file was not created.".into())
			}
		}
		MediaType::Video => {
			// ffmpeg bs
			let mode = std::env::var("MODE").unwrap_or("CPU".to_string());

			// write file to temporary folder
			let out_path = match mode.as_str() {
				"NVIDIA" => format!("{}/output.mp4", &hash),
				"AMD" => format!("{}/output.mp4", &hash),
				_ => format!("{}/output.webm", &hash),
			};
			let file_path = format!("{}/input", &hash);
			tokio::fs::create_dir(&hash).await?;
			tokio::fs::write(&file_path, blob).await?;

			defer! {
				// delete files
				let _ = std::fs::remove_dir_all(&hash);
			}

			// get media information
			let media_info = { MediaInfo::new(file_path.as_str()).await? };

			// debug!("{media_info:?}");

			// set a ratio of 80% video, 20% audio (prioritise video if audio max bitrate is reached)
			// cap resolution at 1080p
			// cap at 30fps

			let target_size = ByteSize::mib(16).as_u64();

			// framerate shicanery (cap out at 30fps, try to get half the original framerate to allow us to just copy every 2nd frame)
			let target_fps = {
				// try and cleanly halve framerate to a sane framerate (optimal for 60fps)
				let halved_framerate = media_info.fps / 2f64;
				let optimal_framerate = if halved_framerate < 30f64 && halved_framerate > 23f64 {
					halved_framerate
				} else {
					media_info.fps
				};

				// clamp it
				num::clamp(optimal_framerate, 1f64, 30f64)
			};

			// bitrate shicanery (allocate space to both video and audio)
			// audio should get at most 20% of the available space, capping out at 64kbps
			// video should get the entire rest of the available space.
			// we need to find a good threshold to cut off audio quality at.
			// we could also retrieve the original bitrates.
			// clamp the audio bitrate to 64kbps. calculate the size difference of the audio stream to get the absolute space available to the video stream.
			// suggestion: after calculating the bitrates, check the ratio and lower the video resolution if the video to audio ratio is too low
			let target_bitrates: (u64, u64) = {
				let size_ratio = target_size as f64 / blob.len() as f64;

				let video_bitrate: u64 = (media_info.bitrates.0 as f64 * size_ratio) as u64;
				let audio_bitrate: u64 = (media_info.bitrates.1 as f64 * size_ratio) as u64;

				let audio_bitrate = num::clamp(
					audio_bitrate,
					ByteSize::kb(28).as_u64() * 8,
					ByteSize::kb(64).as_u64() * 8,
				);

				let estimated_size = (
					((video_bitrate as f64 / 8f64) * media_info.len.as_secs_f64()) as u64,
					((audio_bitrate as f64 / 8f64) * media_info.len.as_secs_f64()) as u64,
				);

				if estimated_size.0 + estimated_size.1 > target_size {
					// the available space excluding audio stream
					let available_space = target_size - estimated_size.1;

					(
						((available_space as f64 * 8f64) / media_info.len.as_secs_f64()) as u64,
						audio_bitrate,
					)
				} else {
					(video_bitrate, audio_bitrate)
				}
			};

			// resolution shicanery (clamp to 1080p)
			let target_resolution = {
				let aspect_ratio: f64 =
					media_info.resolution.0 as f64 / media_info.resolution.1 as f64;

				// if theres more than one byte of audio per 8 bytes of video,
				// we lower the resolution.
				let min_resolution: (u64, u64) = (800, 450);

				let max_resolution: (u64, u64) = if target_bitrates.0 / target_bitrates.1 < 8 {
					(1280, 720)
				} else {
					(1920, 1080)
				};

				let halved_resolution: (u64, u64) =
					(media_info.resolution.0 / 2, media_info.resolution.1 / 2);

				if halved_resolution.0 > min_resolution.0
					&& halved_resolution.0 < max_resolution.0
					&& halved_resolution.1 / 2 > min_resolution.1
					&& halved_resolution.1 / 2 < max_resolution.1
				{
					// halved canvas size is within limits
					halved_resolution
				} else {
					// clamp width, then calculate a height that would preserve aspect ratio
					let fixed_width =
						num::clamp(media_info.resolution.0, min_resolution.0, max_resolution.0);
					let fixed_height = (media_info.resolution.1 as f64 * aspect_ratio) as u64;

					// clamp height if it still exceeds our maximum.
					// this will break the aspect ratio.
					let fixed_height = num::clamp(fixed_height, min_resolution.1, max_resolution.1);

					(fixed_width, fixed_height)
				}
			};

			let video_bitrate_string = format!(
				"{}K",
				if mode == "CPU" {
					target_bitrates.0 / 1000
				} else {
					((target_bitrates.0 / 1000) as f64 * 0.6f64) as u64
				}
			);
			let audio_bitrate_string = format!("{}K", target_bitrates.1 / 1000);

			let fps_string = format!("fps={target_fps}");

			let resolution_string = format!("{}x{}", target_resolution.0, target_resolution.1);

			debug!(
				"Original Media ({}x{}, {:.2}s, {}kbps video, {}kbps audio, {}kb) -> Target Media ({}x{}, {}s, {}kbps video, {}kbps audio, {}kb)",
				media_info.resolution.0, media_info.resolution.1, media_info.len.as_secs_f64(), media_info.bitrates.0 / 1000, media_info.bitrates.1 / 1000, blob.len() / 1000, target_resolution.0, target_resolution.1, media_info.len.as_secs_f64(), target_bitrates.0 / 1000, target_bitrates.1 / 1000, target_size / 1000
			);

			let mut pass_args = vec![
				"-nostats",                    // disable stats
				"-hide_banner",                // hide ffmpeg version banner
				"-i",                          // input file path
				file_path.as_str(),            // = the dropped file's path
				"-c:a",                        // audio codec
				"libopus",                     // = libopus
				"-ac",                         // audio channels
				"1",                           // = 1
				"-b:a",                        // audio bitrate
				audio_bitrate_string.as_str(), // = our calculated optimal bitrate
				"-c:v",                        // video codec
			];

			if mode == "NVIDIA" {
				pass_args.insert(2, "-hwaccel");
				pass_args.insert(3, "cuda");
			}

			let codec = match mode.as_str() {
				"NVIDIA" => "h264_nvenc",
				"AMD" => "h264_amf",
				_ => {
					// enable VP9 row multithreading
					let temp = pass_args.pop();
					pass_args.push("-row-mt");
					pass_args.push("1");
					pass_args.push(temp.unwrap());
					"libvpx-vp9"
				}
			};

			pass_args.push(codec);

			let remaining_args = vec![
				"-b:v",                        // video bitrate
				video_bitrate_string.as_str(), // = our calculated optimal bitrate
				"-minrate",                    // CBR min rate
				video_bitrate_string.as_str(), // = our calculated optimal bitrate
				"-maxrate",                    // CBR max rate
				video_bitrate_string.as_str(), // = our calculated optimal bitrate
				"-bufsize",                    // CBR buffer size
				"1M",                          // = 100k
				"-filter:v",                   // the video framerate
				fps_string.as_str(),           // = our potentially reduced framerate
				"-s",                          // the video frame size
				resolution_string.as_str(),    // = our potentially lowered frame size
				"-deadline",                   // deadline/cpu target
				"good",                        // = take as long as needed for best compression
				"-pix_fmt",                    // pixel format
				"yuv420p",                     // = 4:2:0 YUV
				"-sn",                         // strip all subtitle tracks
				"-map",                        // only process the first video track
				"0:v:0",                       //
				"-map",                        // only process the first audio track
				"0:a:0",                       //
				out_path.as_str(),
			];

			pass_args.extend_from_slice(&remaining_args);

			let _output = async_process::Command::new("ffmpeg")
				.args(pass_args)
				.output()
				.await?;

			debug!("{}", unsafe { String::from_utf8_unchecked(_output.stdout) });
			debug!("{}", unsafe { String::from_utf8_unchecked(_output.stderr) });

			// read file out
			let file_blob = tokio::fs::read(out_path).await?;

			assert!(file_blob.len() < ByteSize::mib(20).as_u64() as usize);

			debug!(
				"Result: {} bytes -> {} bytes ({:.3}%)",
				blob.len(),
				file_blob.len(),
				(file_blob.len() / blob.len()) * 100
			);

			if file_blob.len() > blob.len() {
				return Err("file increased in size!".into());
			}

			if !file_blob.is_empty() {
				Ok(file_blob)
			} else {
				Err("file was not created.".into())
			}
		}
	}
}

#[actix_web::test]
async fn test_mediainfo() {
	let result = MediaInfo::new("src/test.mp4").await.unwrap();

	assert_eq!(result.bitrates, (19117109, 189461));
	assert_eq!(result.fps, 59.94f64);
	assert_eq!(result.len, Duration::from_secs_f64(34.098f64));
	assert_eq!(result.resolution, (1920, 1080));
}

#[actix_web::test]
async fn test_compression() {
	let blob = include_bytes!("test.mp4");

	let out = encode_media(MediaType::Video, "test".into(), blob).await;

	if out.is_err() {
		dbg!(&out);
	}

	assert!(out.is_ok());
}

#[actix_web::test]
async fn test_compression_image() {
	let blob = include_bytes!("test.png");

	let out = encode_media(MediaType::Image, "test".into(), blob).await;

	if out.is_err() {
		dbg!(&out);
	}

	assert!(out.is_ok());
}
