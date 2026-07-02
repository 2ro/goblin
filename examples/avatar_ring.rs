//! G1 sizing-checkpoint harness: renders the REAL `avatar_tex` (custom-image
//! avatar + username conic ring) and `gradient_avatar` across every size the
//! app uses, so the ring thickness/inset can be dialed in by eye.
//! Run: `cargo run --example avatar_ring` (screenshots taken externally).

use eframe::egui;
use grim::gui::views::goblin::widgets as w;

const SIZES: [f32; 6] = [28.0, 40.0, 48.0, 56.0, 72.0, 96.0];
const NAMES: [&str; 3] = ["alice", "bob", "carmen"];

struct App {
	tex: Vec<egui::TextureHandle>,
}

/// A synthetic "profile photo": diagonal two-tone blend with a light disc, so
/// the ring is judged against something photo-like rather than a flat fill.
fn photo(ctx: &egui::Context, name: &str, a: [u8; 3], b: [u8; 3]) -> egui::TextureHandle {
	const N: usize = 128;
	let mut px = Vec::with_capacity(N * N);
	for y in 0..N {
		for x in 0..N {
			let t = (x + y) as f32 / (2 * N) as f32;
			let mut r = a[0] as f32 * (1.0 - t) + b[0] as f32 * t;
			let mut g = a[1] as f32 * (1.0 - t) + b[1] as f32 * t;
			let mut bl = a[2] as f32 * (1.0 - t) + b[2] as f32 * t;
			let dx = x as f32 - 44.0;
			let dy = y as f32 - 40.0;
			if (dx * dx + dy * dy).sqrt() < 26.0 {
				r = (r + 90.0).min(255.0);
				g = (g + 90.0).min(255.0);
				bl = (bl + 90.0).min(255.0);
			}
			px.push(egui::Color32::from_rgb(r as u8, g as u8, bl as u8));
		}
	}
	let img = egui::ColorImage {
		size: [N, N],
		source_size: egui::Vec2::splat(N as f32),
		pixels: px,
	};
	ctx.load_texture(name.to_string(), img, Default::default())
}

impl App {
	fn new(cc: &eframe::CreationContext) -> Self {
		egui_extras::install_image_loaders(&cc.egui_ctx);
		let tex = vec![
			photo(&cc.egui_ctx, "alice", [180, 120, 90], [90, 60, 120]),
			photo(&cc.egui_ctx, "bob", [70, 110, 160], [40, 160, 120]),
			photo(&cc.egui_ctx, "carmen", [160, 70, 90], [220, 170, 80]),
		];
		Self { tex }
	}
}

impl eframe::App for App {
	fn update(&mut self, ctx: &egui::Context, _f: &mut eframe::Frame) {
		egui::CentralPanel::default()
			.frame(egui::Frame::default().fill(egui::Color32::from_rgb(0xFA, 0xFA, 0xF7)))
			.show(ctx, |ui| {
				ui.add_space(10.0);
				ui.heading(
					"G1 avatar ring — sizing sheet (thickness = max(1, size*0.06), gap = max(1, size*0.03))",
				);
				ui.add_space(12.0);
				for (i, name) in NAMES.iter().enumerate() {
					ui.horizontal(|ui| {
						ui.add_space(12.0);
						ui.label(format!("{name:>7}"));
						for size in SIZES {
							ui.add_space(14.0);
							w::avatar_tex(ui, &self.tex[i], name, size);
						}
					});
					ui.add_space(14.0);
				}
				ui.separator();
				ui.label("anonymous npub (grinmark gradient, ring-less):");
				ui.add_space(8.0);
				ui.horizontal(|ui| {
					ui.add_space(12.0);
					ui.label("        ");
					for (i, size) in SIZES.iter().enumerate() {
						ui.add_space(14.0);
						w::gradient_avatar(ui, &format!("{i}deadbeef{i}"), *size);
					}
				});
				ui.add_space(14.0);
				ui.label("named account (SAME gradient, unchanged) + username ring:");
				ui.add_space(8.0);
				for name in NAMES {
					ui.horizontal(|ui| {
						ui.add_space(12.0);
						ui.label(format!("{name:>7}"));
						for size in SIZES {
							ui.add_space(14.0);
							w::gradient_avatar_ringed(ui, "deadbeefcafe", name, size);
						}
					});
					ui.add_space(6.0);
				}
				ui.add_space(10.0);
				ui.horizontal(|ui| {
					ui.add_space(12.0);
					ui.label("sizes:  ");
					for size in SIZES {
						ui.add_space(14.0);
						ui.allocate_ui(egui::Vec2::new(size, 16.0), |ui| {
							ui.centered_and_justified(|ui| ui.small(format!("{size}")));
						});
					}
				});
			});
	}
}

fn main() -> eframe::Result {
	let opts = eframe::NativeOptions {
		viewport: egui::ViewportBuilder::default().with_inner_size([900.0, 640.0]),
		..Default::default()
	};
	eframe::run_native(
		"avatar-ring",
		opts,
		Box::new(|cc| Ok(Box::new(App::new(cc)))),
	)
}
