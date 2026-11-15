use imgui::Ui;

fn run_rows(ui: &Ui, rows: &[(&str, usize)]) {
    let mut log: Vec<String> = Vec::new();
    for (label, buttons) in rows {
        ui.text(*label);
        ui.same_line();
        let text_rect = (
            ui.item_rect_min(),
            ui.item_rect_max(),
            ui.text_line_height(),
        );
        let cursor = ui.cursor_pos();
        let text_height = ui.text_line_height();
        let button_height = ui.frame_height();
        let offset = (button_height - text_height) * -0.5;
        ui.set_cursor_pos([cursor[0], cursor[1] + offset]);
        ui.button("Restore");
        let restore = (ui.item_rect_min(), ui.item_rect_max(), ui.frame_height());
        ui.same_line();
        if *buttons == 2 {
            ui.button("Delete forever");
            let del = (ui.item_rect_min(), ui.item_rect_max(), ui.frame_height());
            log.push(format!(
                "row '{label}': text {text_rect:?} | restore {restore:?} | delete {del:?} | next_cursor {:?}",
                ui.cursor_pos()
            ));
        } else {
            ui.button("Confirm?");
            ui.same_line();
            ui.button("Cancel");
            let cancel = (ui.item_rect_min(), ui.item_rect_max(), ui.frame_height());
            log.push(format!(
                "row '{label}': text {text_rect:?} | restore {restore:?} | cancel {cancel:?} | next_cursor {:?}",
                ui.cursor_pos()
            ));
        }
    }
    for l in &log {
        println!("{l}");
    }
}

#[test]
#[ignore = "layout probe: prints geometry, asserts nothing"]
fn probe_trash_row_geometry() {
    let mut ctx = imgui::Context::create();
    ctx.io_mut().display_size = [1024.0, 768.0];
    ctx.style_mut().frame_padding = [8.0, 4.0];
    ctx.style_mut().item_spacing = [8.0, 4.0];
    let _tex = ctx.fonts().build_rgba32_texture();
    let ui = ctx.frame();
    ui.window("Aegis")
        .position([0.0, 0.0], imgui::Condition::Always)
        .size([1024.0, 768.0], imgui::Condition::Always)
        .build(|| {
            run_rows(
                ui,
                &[
                    ("[CARD] wallet — trashed today", 2),
                    ("github — trashed 3 days ago", 2),
                    ("wifi home — trashed 9 days ago", 1),
                ],
            );
        });
}
