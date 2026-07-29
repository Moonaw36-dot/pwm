#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod app;
mod clipboard;
mod config;
mod file_ops;
mod input;
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
use winit::platform::modifier_supplement::KeyEventExtModifierSupplement;
use winit::{
    event::{Event, WindowEvent},
    event_loop::EventLoop,
    keyboard::{Key as WinitKey, NamedKey},
    window::WindowBuilder,
};

use app::AppState;
use ui::build_ui;

struct ArboardClipboard(arboard::Clipboard);

impl imgui::ClipboardBackend for ArboardClipboard {
    fn get(&mut self) -> Option<String> {
        self.0.get_text().ok()
    }
    fn set(&mut self, value: &str) {
        let _ = self.0.set_text(value);
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let event_loop = EventLoop::new().unwrap();
    let window_builder =
        WindowBuilder::new()
            .with_title("Aegis")
            .with_inner_size(winit::dpi::LogicalSize::new(
                theme::WINDOW_WIDTH,
                theme::WINDOW_HEIGHT,
            ));

    let display_builder = DisplayBuilder::new().with_window_builder(Some(window_builder));
    let (window, gl_config) = display_builder
        .build(&event_loop, ConfigTemplateBuilder::new(), |mut configs| {
            configs.next().unwrap()
        })
        .unwrap();
    let window = window.unwrap();

    let gl_display = gl_config.display();
    let context_attribs = ContextAttributesBuilder::new().build(Some(window.raw_window_handle()));
    let gl_context = unsafe {
        gl_display
            .create_context(&gl_config, &context_attribs)
            .unwrap()
    };

    let size = window.inner_size();
    let surface_attribs = SurfaceAttributesBuilder::<WindowSurface>::new().build(
        window.raw_window_handle(),
        NonZeroU32::new(size.width.max(1)).unwrap(),
        NonZeroU32::new(size.height.max(1)).unwrap(),
    );
    let gl_surface = unsafe {
        gl_display
            .create_window_surface(&gl_config, &surface_attribs)
            .unwrap()
    };

    let gl_context = gl_context.make_current(&gl_surface).unwrap();

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
    if let Ok(clipboard) = arboard::Clipboard::new() {
        imgui_ctx.set_clipboard_backend(ArboardClipboard(clipboard));
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

    let mut renderer = imgui_glow_renderer::AutoRenderer::initialize(gl, &mut imgui_ctx).unwrap();

    let gl_rc = renderer.gl_context().clone();
    let card_texture = texture::load_from_bytes(
        &gl_rc,
        renderer.texture_map_mut(),
        include_bytes!("../assets/icons8-magnetic-card-48.png"),
    );

    let mut last_frame = std::time::Instant::now();
    let mut state = AppState::new();
    state.card_texture = card_texture;
    theme::apply(imgui_ctx.style_mut(), state.light_mode);

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
                        | WindowEvent::MouseInput { .. }
                        | WindowEvent::CursorMoved { .. }
                        | WindowEvent::MouseWheel { .. },
                    ..
                }
            ) {
                state.vault.last_activity = std::time::Instant::now();
            }

            match event {
                Event::WindowEvent {
                    event: WindowEvent::Resized(new_size),
                    ..
                } => {
                    if new_size.width > 0 && new_size.height > 0 {
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
                }
                Event::NewEvents(_) => {
                    imgui_ctx.io_mut().update_delta_time(last_frame.elapsed());
                    last_frame = std::time::Instant::now();
                }
                Event::AboutToWait => {
                    window.request_redraw();
                }
                Event::WindowEvent {
                    event: WindowEvent::RedrawRequested,
                    ..
                } => {
                    theme::apply(imgui_ctx.style_mut(), state.light_mode);
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
                    target.exit();
                }
                _ => {}
            }
        })
        .unwrap();
}
