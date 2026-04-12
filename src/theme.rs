pub const WINDOW_WIDTH: f32 = 1024.0;
pub const WINDOW_HEIGHT: f32 = 768.0;
pub const FONT_SIZE_PT: f32 = 15.0;

pub const MODAL_WIDTH_STANDARD: f32 = 400.0;
pub const MODAL_WIDTH_GENERATOR: f32 = 440.0;
pub const MODAL_WIDTH_SETTINGS: f32 = 300.0;

pub const CUSTOM_FIELD_NAME_WIDTH: f32 = 150.0;
pub const CUSTOM_FIELD_VALUE_WIDTH: f32 = 180.0;

pub const LINK_COLOR: [f32; 4] = [0.27, 0.67, 1.0, 1.0];
pub const ERROR_COLOR: [f32; 4] = [1.0, 0.0, 0.0, 1.0];

pub fn apply(style: &mut imgui::Style) {
    style.window_rounding = 6.0;
    style.popup_rounding = 6.0;
    style.tab_rounding = 4.0;
    style.child_rounding = 4.0;
    style.frame_rounding = 4.0;
    style.anti_aliased_lines = true;
    style.anti_aliased_fill = true;
    style.frame_padding = [6.0, 3.0];
    style.window_padding = [6.0, 3.0];

    let c = &mut style.colors;
    c[imgui::StyleColor::WindowBg as usize]          = [0.10, 0.10, 0.10, 1.0];
    c[imgui::StyleColor::ModalWindowDimBg as usize]  = [0.20, 0.20, 0.20, 0.3];
    c[imgui::StyleColor::TitleBgActive as usize]     = [0.10, 0.10, 0.10, 1.0];
    c[imgui::StyleColor::FrameBg as usize]           = [0.15, 0.15, 0.15, 1.0];
    c[imgui::StyleColor::FrameBgHovered as usize]    = [0.20, 0.20, 0.20, 1.0];
    c[imgui::StyleColor::FrameBgActive as usize]     = [0.25, 0.25, 0.25, 1.0];
    c[imgui::StyleColor::Button as usize]            = [0.13, 0.13, 0.13, 1.0];
    c[imgui::StyleColor::ButtonHovered as usize]     = [0.30, 0.30, 0.30, 1.0];
    c[imgui::StyleColor::ButtonActive as usize]      = [0.60, 0.60, 0.60, 1.0];
    c[imgui::StyleColor::SliderGrab as usize]        = [0.40, 0.40, 0.40, 1.0];
    c[imgui::StyleColor::SliderGrabActive as usize]  = [0.60, 0.60, 0.60, 1.0];
    c[imgui::StyleColor::Tab as usize]               = [0.14, 0.14, 0.14, 1.0];
    c[imgui::StyleColor::TabActive as usize]         = [0.25, 0.25, 0.25, 1.0];
    c[imgui::StyleColor::TabHovered as usize]        = [0.20, 0.20, 0.20, 1.0];
    c[imgui::StyleColor::Border as usize]            = [0.08, 0.08, 0.08, 1.0];
    c[imgui::StyleColor::Separator as usize]         = [0.18, 0.18, 0.18, 1.0];
    c[imgui::StyleColor::MenuBarBg as usize]         = [0.12, 0.12, 0.12, 0.8];
    c[imgui::StyleColor::HeaderHovered as usize]     = [0.18, 0.18, 0.18, 1.0];
    c[imgui::StyleColor::ResizeGrip as usize]        = [0.12, 0.12, 0.12, 1.0];
    c[imgui::StyleColor::ResizeGripActive as usize]  = [0.14, 0.14, 0.14, 1.0];
    c[imgui::StyleColor::ResizeGripHovered as usize] = [0.15, 0.15, 0.15, 1.0];
}
