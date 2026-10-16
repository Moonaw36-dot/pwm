#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod app;
mod clipboard;
mod config;
mod file_ops;
mod input;
mod locked_buf;
mod modals;
mod models;
mod strength;
mod texture;
mod theme;
mod ui;
mod ui_tabs;

use glow::HasContext;
use glutin::{
    config::ConfigTemplateBuilder,
    context::ContextAttributesBuilder,
    display::GetGlDisplay,
    prelude::*,
    surface::{SurfaceAttributesBuilder, WindowSurface},
};
use glutin_winit::DisplayBuilder;
use imgui_winit_support::{HiDpiMode, WinitPlatform};
use raw_window_handle::HasRawWindowHandle;
use std::num::NonZeroU32;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64},
};
use winit::platform::modifier_supplement::KeyEventExtModifierSupplement;
use winit::{
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    keyboard::{Key as WinitKey, NamedKey},
    window::WindowBuilder,
};

use app::AppState;
use std::sync::atomic::Ordering;
use ui::build_ui;

struct ArboardClipboard {
    clipboard: arboard::Clipboard,
    external_copy_pending: Arc<AtomicBool>,
    external_copy_fingerprint: Arc<AtomicU64>,
}

impl imgui::ClipboardBackend for ArboardClipboard {
    fn get(&mut self) -> Option<String> {
        self.clipboard.get_text().ok()
    }
    fn set(&mut self, value: &str) {
        if crate::clipboard::set_excluded_from_history(&mut self.clipboard, value).is_ok() {
            self.external_copy_fingerprint
                .store(crate::clipboard::fingerprint(value), Ordering::Release);
            self.external_copy_pending.store(true, Ordering::Release);
        }
    }
}

fn report_startup_error(context: &str, err: impl std::fmt::Debug) {
    let detail = format!("{err:?}");
    log::error!("{context}: {detail}");
    eprintln!("Aegis failed to start ({context}): {detail}");
    if detail.contains("NoWaylandLib")
        || detail.contains("WaylandError")
        || detail.contains("libwayland")
        || detail.contains("NoXLib")
        || detail.contains("XOpenDisplay")
    {
        eprintln!(
            "Missing windowing libraries. On NixOS do not run target/release/aegis directly;\n\
             use the launcher so the required X11/Wayland/OpenGL libraries are present:\n\n  \
             cargo build --release\n  \
             ./aegis\n\n\
             If you are already inside `nix-shell shell.nix`, `cargo run --release` also works.\n\
             On Debian/Ubuntu-like systems install:\n\n  \
             sudo apt install libgl1-mesa-dev libglu1-mesa-dev libxkbcommon-dev libwayland-dev \\\n  \
             libx11-dev libxcb1-dev libxrandr-dev libxi-dev libxcursor-dev libxext-dev libxfixes-dev libxrender-dev"
        );
    } else if detail.contains("no available pixel format")
        || detail.contains("NotFound")
        || detail.contains("BadPixelFormat")
    {
        eprintln!(
            "No suitable OpenGL configuration found. A working X11 or Wayland session and\n\
             OpenGL-capable graphics drivers are required."
        );
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let event_loop = match EventLoop::new() {
        Ok(event_loop) => event_loop,
        Err(err) => {
            report_startup_error("could not initialize windowing backend", &err);
            std::process::exit(1);
        }
    };
    let window_builder =
        WindowBuilder::new()
            .with_title("Aegis")
            .with_inner_size(winit::dpi::LogicalSize::new(
                theme::WINDOW_WIDTH,
                theme::WINDOW_HEIGHT,
            ));

    let display_builder = DisplayBuilder::new().with_window_builder(Some(window_builder));
    let (window, gl_config) =
        match display_builder.build(&event_loop, ConfigTemplateBuilder::new(), |mut configs| {
            configs.next().unwrap_or_else(|| {
                report_startup_error(
                    "no suitable OpenGL configuration",
                    "no available pixel format",
                );
                std::process::exit(1);
            })
        }) {
            Ok((window, gl_config)) => (window, gl_config),
            Err(err) => {
                report_startup_error("could not create OpenGL display", &err);
                std::process::exit(1);
            }
        };
    let window = window.unwrap_or_else(|| {
        report_startup_error("could not create window", "window builder returned None");
        std::process::exit(1);
    });

    let gl_display = gl_config.display();
    let context_attribs = ContextAttributesBuilder::new().build(Some(window.raw_window_handle()));
    let gl_context = unsafe {
        match gl_display.create_context(&gl_config, &context_attribs) {
            Ok(context) => context,
            Err(err) => {
                report_startup_error("could not create OpenGL context", &err);
                std::process::exit(1);
            }
        }
    };

    let size = window.inner_size();
    let surface_attribs = SurfaceAttributesBuilder::<WindowSurface>::new().build(
        window.raw_window_handle(),
        NonZeroU32::new(size.width.max(1)).unwrap_or_else(|| {
            report_startup_error("invalid window size", "window width/height is zero");
            std::process::exit(1);
        }),
        NonZeroU32::new(size.height.max(1)).unwrap_or_else(|| {
            report_startup_error("invalid window size", "window width/height is zero");
            std::process::exit(1);
        }),
    );
    let gl_surface = unsafe {
        match gl_display.create_window_surface(&gl_config, &surface_attribs) {
            Ok(surface) => surface,
            Err(err) => {
                report_startup_error("could not create OpenGL window surface", &err);
                std::process::exit(1);
            }
        }
    };

    let gl_context = match gl_context.make_current(&gl_surface) {
        Ok(context) => context,
        Err(err) => {
            report_startup_error("could not activate OpenGL context", &err);
            std::process::exit(1);
        }
    };

    let gl = unsafe {
        glow::Context::from_loader_function(|s| {
            std::ffi::CString::new(s)
                .ok()
                .map(|cs| gl_display.get_proc_address(&cs))
                .unwrap_or(std::ptr::null())
        })
    };

    // imgui setup
    let mut imgui_ctx = imgui::Context::create();
    imgui_ctx.set_ini_filename(None);
    let mut state = AppState::new();
    if let Ok(clipboard) = arboard::Clipboard::new() {
        imgui_ctx.set_clipboard_backend(ArboardClipboard {
            clipboard,
            external_copy_pending: state.clipboard.backend_signal(),
            external_copy_fingerprint: state.clipboard.backend_fingerprint_signal(),
        });
    }

    let mut platform = WinitPlatform::init(&mut imgui_ctx);
    platform.attach_window(imgui_ctx.io_mut(), &window, HiDpiMode::Default);

    let hidpi = platform.hidpi_factor();
    let font_size = (theme::FONT_SIZE_PT as f64 * hidpi) as f32;
    imgui_ctx.fonts().add_font(&[imgui::FontSource::TtfData {
        data: include_bytes!("../assets/Inter_24pt-Regular.ttf"),
        size_pixels: font_size,
        config: Some(imgui::FontConfig {
            oversample_h: 2,
            oversample_v: 2,
            pixel_snap_h: true,
            ..Default::default()
        }),
    }]);
    imgui_ctx.io_mut().font_global_scale = (1.0 / hidpi) as f32;

    let mut renderer = match imgui_glow_renderer::AutoRenderer::initialize(gl, &mut imgui_ctx) {
        Ok(renderer) => renderer,
        Err(err) => {
            report_startup_error("could not initialize OpenGL renderer", &err);
            std::process::exit(1);
        }
    };

    let gl_rc = renderer.gl_context().clone();
    let card_texture = texture::load_from_bytes(
        &gl_rc,
        renderer.texture_map_mut(),
        include_bytes!("../assets/icons8-magnetic-card-48.png"),
    );

    let mut last_frame = std::time::Instant::now();
    let mut next_tick = std::time::Instant::now() + std::time::Duration::from_secs(1);
    state.card_texture = card_texture;
    theme::apply(imgui_ctx.style_mut(), state.light_mode);
    let mut applied_light_mode = state.light_mode;

    event_loop
        .run(move |event, target| {
            if let Event::WindowEvent {
                event: WindowEvent::KeyboardInput { ref event, .. },
                ..
            } = event
            {
                let pressed = event.state == winit::event::ElementState::Pressed;
                let key = event.key_without_modifiers();
                let ctrl_held = imgui_ctx.io().key_ctrl;
                let io = imgui_ctx.io_mut();

                if pressed
                    && !ctrl_held
                    && let Some(txt) = &event.text
                {
                    for ch in txt.chars() {
                        if ch != '\u{7f}' {
                            io.add_input_character(ch);
                        }
                    }
                }

                match key.as_ref() {
                    WinitKey::Named(NamedKey::Shift) => {
                        io.add_key_event(imgui::Key::ModShift, pressed)
                    }
                    WinitKey::Named(NamedKey::Control) => {
                        io.add_key_event(imgui::Key::ModCtrl, pressed)
                    }
                    WinitKey::Named(NamedKey::Alt) => io.add_key_event(imgui::Key::ModAlt, pressed),
                    WinitKey::Named(NamedKey::Super) => {
                        io.add_key_event(imgui::Key::ModSuper, pressed)
                    }
                    _ => {}
                }

                if let Some(imgui_key) = input::to_imgui_key(key, event.location) {
                    io.add_key_event(imgui_key, pressed);
                }
            } else {
                platform.handle_event(imgui_ctx.io_mut(), &window, &event);
            }

            if matches!(
                event,
                Event::WindowEvent {
                    event: WindowEvent::KeyboardInput { .. }
                        | WindowEvent::Ime { .. }
                        | WindowEvent::MouseInput { .. }
                        | WindowEvent::CursorMoved { .. }
                        | WindowEvent::MouseWheel { .. }
                        | WindowEvent::Resized { .. },
                    ..
                }
            ) {
                state.vault.last_activity = std::time::Instant::now();
                window.request_redraw();
            }

            match event {
                Event::WindowEvent {
                    event: WindowEvent::Resized(new_size),
                    ..
                } if new_size.width > 0 && new_size.height > 0 => {
                    gl_surface.resize(
                        &gl_context,
                        NonZeroU32::new(new_size.width).unwrap(),
                        NonZeroU32::new(new_size.height).unwrap(),
                    );

                    unsafe {
                        renderer.gl_context().viewport(
                            0,
                            0,
                            new_size.width as i32,
                            new_size.height as i32,
                        );
                    }
                }
                Event::NewEvents(_) => {
                    imgui_ctx.io_mut().update_delta_time(last_frame.elapsed());
                    last_frame = std::time::Instant::now();
                }
                Event::AboutToWait => {
                    // Redraws are driven by input events, plus this one-second
                    // tick that keeps timers running while idle (TOTP
                    // countdown, auto-lock, clipboard auto-clear). Requesting
                    // unconditionally would redraw at full speed forever.
                    target.set_control_flow(ControlFlow::WaitUntil(
                        std::time::Instant::now() + std::time::Duration::from_secs(1),
                    ));
                    if std::time::Instant::now() >= next_tick {
                        next_tick = std::time::Instant::now() + std::time::Duration::from_secs(1);
                        window.request_redraw();
                    }
                }
                Event::WindowEvent {
                    event: WindowEvent::RedrawRequested,
                    ..
                } => {
                    if state.light_mode != applied_light_mode {
                        theme::apply(imgui_ctx.style_mut(), state.light_mode);
                        applied_light_mode = state.light_mode;
                    }
                    platform.prepare_frame(imgui_ctx.io_mut(), &window).unwrap();
                    let ui = imgui_ctx.frame();

                    build_ui(ui, &mut state);

                    if state.should_exit {
                        state.close_file();
                        target.exit();
                    }

                    platform.prepare_render(ui, &window);
                    let draw_data = imgui_ctx.render();

                    unsafe {
                        let gl = renderer.gl_context();
                        gl.bind_framebuffer(glow::FRAMEBUFFER, None);
                        let [r, g, b, a] = theme::clear_color(state.light_mode);
                        gl.clear_color(r, g, b, a);
                        gl.clear(glow::COLOR_BUFFER_BIT);
                    }

                    renderer.render(draw_data).unwrap();

                    unsafe {
                        renderer
                            .gl_context()
                            .bind_framebuffer(glow::FRAMEBUFFER, None);
                    }

                    gl_surface.swap_buffers(&gl_context).unwrap();
                }
                Event::WindowEvent {
                    event: WindowEvent::CloseRequested,
                    ..
                } => {
                    // Wipe any copied secret from the clipboard before exiting.
                    state.close_file();
                    target.exit();
                }
                _ => {}
            }
        })
        .unwrap();
}
