#![windows_subsystem = "windows"]

mod app;
mod clipboard;
mod config;
mod file_ops;
mod input;
mod modals;
mod strength;
mod theme;
mod models;
mod ui;
mod ui_tabs;

use glutin::{
    config::ConfigTemplateBuilder,
    context::ContextAttributesBuilder,
    display::GetGlDisplay,
    prelude::*,
    surface::{SurfaceAttributesBuilder, WindowSurface},
};
use glow::HasContext;
use glutin_winit::DisplayBuilder;
use imgui_winit_support::{HiDpiMode, WinitPlatform};
use raw_window_handle::HasRawWindowHandle;
use std::num::NonZeroU32;
use winit::{
    event::{Event, WindowEvent},
    event_loop::EventLoop,
    keyboard::{Key as WinitKey, NamedKey},
    window::WindowBuilder,
};
use winit::platform::modifier_supplement::KeyEventExtModifierSupplement;

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
    let event_loop = EventLoop::new().unwrap();
    let window_builder = WindowBuilder::new()
        .with_title("Aegis")
        .with_inner_size(winit::dpi::LogicalSize::new(theme::WINDOW_WIDTH, theme::WINDOW_HEIGHT));

    let display_builder = DisplayBuilder::new().with_window_builder(Some(window_builder));
    let (window, gl_config) = display_builder
        .build(&event_loop, ConfigTemplateBuilder::new(), |mut configs| {
            configs.next().unwrap()
        })
        .unwrap();
    let window = window.unwrap();

    let gl_display = gl_config.display();
    let context_attribs = ContextAttributesBuilder::new()
        .build(Some(window.raw_window_handle()));
    let gl_context = unsafe {
        gl_display.create_context(&gl_config, &context_attribs).unwrap()
    };

    let size = window.inner_size();
    let surface_attribs = SurfaceAttributesBuilder::<WindowSurface>::new().build(
        window.raw_window_handle(),
        NonZeroU32::new(size.width).unwrap(),
        NonZeroU32::new(size.height).unwrap(),
    );
    let gl_surface = unsafe {
        gl_display.create_window_surface(&gl_config, &surface_attribs).unwrap()
    };

    let gl_context = gl_context.make_current(&gl_surface).unwrap();

    let gl = unsafe {
        glow::Context::from_loader_function(|s| {
            gl_display.get_proc_address(&std::ffi::CString::new(s).unwrap())
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

    let mut renderer =
        imgui_glow_renderer::AutoRenderer::initialize(gl, &mut imgui_ctx).unwrap();

    theme::apply(imgui_ctx.style_mut());

    let mut last_frame = std::time::Instant::now();
    let mut state = AppState::new();

    event_loop.run(move |event, target| {
        if let Event::WindowEvent {
            event: WindowEvent::KeyboardInput { ref event, .. }, ..
        } = event {
            let pressed = event.state == winit::event::ElementState::Pressed;
            let key = event.key_without_modifiers();
            let ctrl_held = imgui_ctx.io().key_ctrl;
            let io = imgui_ctx.io_mut();

            if pressed && !ctrl_held && let Some(txt) = &event.text {
                for ch in txt.chars() {
                    if ch != '\u{7f}' {
                        io.add_input_character(ch);
                    }
                }
            }

            match key.as_ref() {
                WinitKey::Named(NamedKey::Shift) => io.add_key_event(imgui::Key::ModShift, pressed),
                WinitKey::Named(NamedKey::Control) => io.add_key_event(imgui::Key::ModCtrl, pressed),
                WinitKey::Named(NamedKey::Alt) => io.add_key_event(imgui::Key::ModAlt, pressed),
                WinitKey::Named(NamedKey::Super) => io.add_key_event(imgui::Key::ModSuper, pressed),
                _ => {}
            }

            if let Some(imgui_key) = input::to_imgui_key(key, event.location) {
                io.add_key_event(imgui_key, pressed);
            }
        } else {
            platform.handle_event(imgui_ctx.io_mut(), &window, &event);
        }

        if matches!(event, Event::WindowEvent {
            event: WindowEvent::KeyboardInput { .. }
                | WindowEvent::MouseInput { .. }
                | WindowEvent::CursorMoved { .. }
                | WindowEvent::MouseWheel { .. },
            ..
        }) {
            state.vault.last_activity = std::time::Instant::now();
        }

        match event {
            Event::NewEvents(_) => {
                imgui_ctx.io_mut().update_delta_time(last_frame.elapsed());
                last_frame = std::time::Instant::now();
            }
            Event::AboutToWait => {
                window.request_redraw();
            }
            Event::WindowEvent {
                event: WindowEvent::RedrawRequested, ..
            } => {
                platform.prepare_frame(imgui_ctx.io_mut(), &window).unwrap();
                let ui = imgui_ctx.frame();

                build_ui(ui, &mut state);

                platform.prepare_render(ui, &window);
                let draw_data = imgui_ctx.render();

                unsafe {
                    let gl = renderer.gl_context();
                    gl.bind_framebuffer(glow::FRAMEBUFFER, None);
                    gl.clear_color(0.1, 0.1, 0.1, 1.0);
                    gl.clear(glow::COLOR_BUFFER_BIT);
                }

                renderer.render(draw_data).unwrap();

                unsafe {
                    renderer.gl_context().bind_framebuffer(glow::FRAMEBUFFER, None);
                }

                gl_surface.swap_buffers(&gl_context).unwrap();
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested, ..
            } => target.exit(),
            _ => {}
        }
    }).unwrap();
}
