pub const WINDOW_WIDTH: f32 = 1024.0;
pub const WINDOW_HEIGHT: f32 = 768.0;
pub const FONT_SIZE_PT: f32 = 15.0;

pub const MODAL_WIDTH_STANDARD: f32 = 400.0;
pub const MODAL_WIDTH_GENERATOR: f32 = 440.0;
pub const MODAL_WIDTH_SETTINGS: f32 = 300.0;

pub const CUSTOM_FIELD_NAME_WIDTH: f32 = 150.0;
pub const CUSTOM_FIELD_VALUE_WIDTH: f32 = 180.0;

pub const SUCCESS_COLOR: [f32; 4] = [0.0, 1.0, 0.0, 1.0];

pub const LINK_COLOR: [f32; 4] = [0.27, 0.67, 1.0, 1.0];
pub const ERROR_COLOR: [f32; 4] = [1.0, 0.0, 0.0, 1.0];

pub fn apply(style: &mut imgui::Style, light_mode: bool) {
    style.window_rounding = 8.0;
    style.popup_rounding = 8.0;
    style.tab_rounding = 6.0;
    style.child_rounding = 6.0;
    style.frame_rounding = 6.0;
    style.scrollbar_rounding = 6.0;
    style.grab_rounding = 4.0;
    style.anti_aliased_lines = true;
    style.anti_aliased_fill = true;
    style.frame_padding = [8.0, 4.0];
    style.window_padding = [10.0, 6.0];
    style.item_spacing = [8.0, 4.0];

    if light_mode {
        style.use_light_colors();
        apply_light_colors(style);
    } else {
        style.use_dark_colors();
        apply_dark_colors(style);
    }
}

pub fn clear_color(light_mode: bool) -> [f32; 4] {
    if light_mode {
        [0.74, 0.74, 0.71, 1.0]
    } else {
        [0.10, 0.10, 0.10, 1.0]
    }
}

fn set(c: &mut [[f32; 4]], idx: imgui::StyleColor, color: [f32; 4]) {
    let i = idx as usize;
    if i < c.len() {
        c[i] = color;
    }
}

fn apply_dark_colors(style: &mut imgui::Style) {
    let c = &mut style.colors;
    set(c, imgui::StyleColor::Text, [0.92, 0.93, 0.96, 1.0]);
    set(c, imgui::StyleColor::TextDisabled, [0.55, 0.57, 0.64, 1.0]);
    set(c, imgui::StyleColor::WindowBg, [0.06, 0.06, 0.10, 1.0]);
    set(c, imgui::StyleColor::ChildBg, [0.06, 0.06, 0.10, 1.0]);
    set(c, imgui::StyleColor::PopupBg, [0.08, 0.08, 0.12, 1.0]);
    set(
        c,
        imgui::StyleColor::ModalWindowDimBg,
        [0.00, 0.00, 0.00, 0.35],
    );
    set(c, imgui::StyleColor::TitleBgActive, [0.06, 0.06, 0.10, 1.0]);
    set(c, imgui::StyleColor::FrameBg, [0.10, 0.10, 0.15, 1.0]);
    set(
        c,
        imgui::StyleColor::FrameBgHovered,
        [0.15, 0.15, 0.20, 1.0],
    );
    set(c, imgui::StyleColor::FrameBgActive, [0.20, 0.20, 0.26, 1.0]);
    set(c, imgui::StyleColor::Button, [0.13, 0.13, 0.18, 1.0]);
    set(c, imgui::StyleColor::ButtonHovered, [0.30, 0.30, 0.36, 1.0]);
    set(c, imgui::StyleColor::ButtonActive, [0.60, 0.60, 0.65, 1.0]);
    set(c, imgui::StyleColor::SliderGrab, [0.35, 0.45, 0.60, 1.0]);
    set(
        c,
        imgui::StyleColor::SliderGrabActive,
        [0.45, 0.55, 0.70, 1.0],
    );
    set(c, imgui::StyleColor::CheckMark, [0.45, 0.55, 0.70, 1.0]);
    set(c, imgui::StyleColor::Tab, [0.06, 0.06, 0.12, 1.0]);
    set(c, imgui::StyleColor::TabActive, [0.12, 0.16, 0.28, 1.0]);
    set(c, imgui::StyleColor::TabHovered, [0.10, 0.12, 0.20, 1.0]);
    set(c, imgui::StyleColor::Border, [0.10, 0.10, 0.16, 1.0]);
    set(c, imgui::StyleColor::Separator, [0.14, 0.14, 0.22, 1.0]);
    set(c, imgui::StyleColor::MenuBarBg, [0.06, 0.06, 0.12, 0.9]);
    set(c, imgui::StyleColor::HeaderHovered, [0.15, 0.15, 0.22, 1.0]);
    set(c, imgui::StyleColor::ResizeGrip, [0.20, 0.20, 0.30, 1.0]);
    set(
        c,
        imgui::StyleColor::ResizeGripActive,
        [0.35, 0.35, 0.50, 1.0],
    );
    set(
        c,
        imgui::StyleColor::ResizeGripHovered,
        [0.25, 0.25, 0.38, 1.0],
    );
}

fn apply_light_colors(style: &mut imgui::Style) {
    let c = &mut style.colors;
    set(c, imgui::StyleColor::Text, [0.08, 0.09, 0.10, 1.0]);
    set(c, imgui::StyleColor::TextDisabled, [0.38, 0.39, 0.40, 1.0]);
    set(c, imgui::StyleColor::WindowBg, [0.79, 0.79, 0.76, 1.0]);
    set(c, imgui::StyleColor::ChildBg, [0.77, 0.77, 0.74, 1.0]);
    set(c, imgui::StyleColor::PopupBg, [0.82, 0.82, 0.79, 1.0]);
    set(c, imgui::StyleColor::Border, [0.48, 0.48, 0.45, 1.0]);
    set(c, imgui::StyleColor::BorderShadow, [0.00, 0.00, 0.00, 0.0]);
    set(c, imgui::StyleColor::FrameBg, [0.68, 0.68, 0.65, 1.0]);
    set(c, imgui::StyleColor::FrameBgHovered, [0.62, 0.63, 0.60, 1.0]);
    set(c, imgui::StyleColor::FrameBgActive, [0.57, 0.58, 0.55, 1.0]);
    set(c, imgui::StyleColor::TitleBg, [0.64, 0.64, 0.61, 1.0]);
    set(c, imgui::StyleColor::TitleBgActive, [0.58, 0.59, 0.57, 1.0]);
    set(c, imgui::StyleColor::TitleBgCollapsed, [0.68, 0.68, 0.65, 1.0]);
    set(c, imgui::StyleColor::MenuBarBg, [0.70, 0.70, 0.67, 1.0]);
    set(c, imgui::StyleColor::ScrollbarBg, [0.74, 0.74, 0.71, 1.0]);
    set(c, imgui::StyleColor::ScrollbarGrab, [0.52, 0.52, 0.50, 1.0]);
    set(c, imgui::StyleColor::ScrollbarGrabHovered, [0.46, 0.47, 0.45, 1.0]);
    set(c, imgui::StyleColor::ScrollbarGrabActive, [0.40, 0.41, 0.39, 1.0]);
    set(c, imgui::StyleColor::CheckMark, [0.20, 0.27, 0.36, 1.0]);
    set(c, imgui::StyleColor::SliderGrab, [0.33, 0.38, 0.47, 1.0]);
    set(c, imgui::StyleColor::SliderGrabActive, [0.25, 0.31, 0.40, 1.0]);
    set(c, imgui::StyleColor::Button, [0.62, 0.63, 0.60, 1.0]);
    set(c, imgui::StyleColor::ButtonHovered, [0.54, 0.56, 0.53, 1.0]);
    set(c, imgui::StyleColor::ButtonActive, [0.47, 0.49, 0.47, 1.0]);
    set(c, imgui::StyleColor::Header, [0.64, 0.65, 0.62, 1.0]);
    set(c, imgui::StyleColor::HeaderHovered, [0.57, 0.58, 0.56, 1.0]);
    set(c, imgui::StyleColor::HeaderActive, [0.50, 0.52, 0.50, 1.0]);
    set(c, imgui::StyleColor::Separator, [0.50, 0.50, 0.47, 1.0]);
    set(c, imgui::StyleColor::SeparatorHovered, [0.42, 0.43, 0.41, 1.0]);
    set(c, imgui::StyleColor::SeparatorActive, [0.36, 0.38, 0.36, 1.0]);
    set(c, imgui::StyleColor::ResizeGrip, [0.53, 0.54, 0.51, 1.0]);
    set(c, imgui::StyleColor::ResizeGripHovered, [0.45, 0.47, 0.44, 1.0]);
    set(c, imgui::StyleColor::ResizeGripActive, [0.37, 0.39, 0.37, 1.0]);
    set(c, imgui::StyleColor::Tab, [0.62, 0.63, 0.60, 1.0]);
    set(c, imgui::StyleColor::TabHovered, [0.55, 0.57, 0.54, 1.0]);
    set(c, imgui::StyleColor::TabActive, [0.78, 0.78, 0.75, 1.0]);
    set(c, imgui::StyleColor::TabUnfocused, [0.66, 0.66, 0.63, 1.0]);
    set(c, imgui::StyleColor::TabUnfocusedActive, [0.73, 0.73, 0.70, 1.0]);
    set(c, imgui::StyleColor::PlotLines, [0.30, 0.35, 0.45, 1.0]);
    set(c, imgui::StyleColor::PlotLinesHovered, [0.20, 0.27, 0.38, 1.0]);
    set(c, imgui::StyleColor::PlotHistogram, [0.36, 0.43, 0.34, 1.0]);
    set(c, imgui::StyleColor::PlotHistogramHovered, [0.28, 0.36, 0.26, 1.0]);
    set(c, imgui::StyleColor::TableHeaderBg, [0.66, 0.66, 0.63, 1.0]);
    set(c, imgui::StyleColor::TableBorderStrong, [0.45, 0.45, 0.43, 1.0]);
    set(c, imgui::StyleColor::TableBorderLight, [0.55, 0.55, 0.52, 1.0]);
    set(c, imgui::StyleColor::TableRowBg, [0.00, 0.00, 0.00, 0.0]);
    set(c, imgui::StyleColor::TableRowBgAlt, [0.70, 0.70, 0.67, 0.45]);
    set(c, imgui::StyleColor::TextSelectedBg, [0.35, 0.42, 0.52, 0.35]);
    set(c, imgui::StyleColor::DragDropTarget, [0.27, 0.34, 0.44, 0.90]);
    set(c, imgui::StyleColor::NavHighlight, [0.27, 0.34, 0.44, 0.80]);
    set(c, imgui::StyleColor::NavWindowingHighlight, [0.12, 0.13, 0.14, 0.70]);
    set(c, imgui::StyleColor::NavWindowingDimBg, [0.20, 0.20, 0.20, 0.20]);
    set(c, imgui::StyleColor::ModalWindowDimBg, [0.12, 0.12, 0.12, 0.35]);
}
