use crate::app::AppState;
use crate::modals::render_strength_bar;
use crate::strength::{GenMode, generate_passphrase, generate_password};
use crate::theme;
use zeroize::Zeroizing;

pub fn generate_password_modal(ui: &imgui::Ui, state: &mut AppState) {
    ui.dummy([theme::MODAL_WIDTH_GENERATOR, 0.0]);

    let mut mode_idx = if state.generator.mode == GenMode::Passphrase {
        1i32
    } else {
        0i32
    };
    ui.radio_button("Random password##mode", &mut mode_idx, 0);
    ui.same_line();
    ui.radio_button("Passphrase##mode", &mut mode_idx, 1);
    state.generator.mode = if mode_idx == 1 {
        GenMode::Passphrase
    } else {
        GenMode::Password
    };

    ui.separator();

    if state.generator.mode == GenMode::Password {
        ui.slider("Length", 8, 64, &mut state.generator.length);
        ui.checkbox("Uppercase (A-Z)", &mut state.generator.uppercase);
        ui.checkbox("Lowercase (a-z)", &mut state.generator.lowercase);
        ui.checkbox("Numbers (0-9)", &mut state.generator.numbers);
        ui.checkbox("Special (!@#...)", &mut state.generator.special);
        ui.checkbox(
            "Ambiguous characters (O0...)",
            &mut state.generator.ambiguous,
        );
    } else {
        ui.slider("Word count", 3, 64, &mut state.generator.word_count);
        ui.input_text("Separator", &mut state.generator.separator)
            .build();
    }

    ui.separator();

    if !state.form.password.is_empty() {
        ui.text_disabled(format!(
            "Generated password: {}",
            "*".repeat(state.form.password.len())
        ));
        let pw = state.form.password.clone();
        let strength = state.cached_strength(&pw);
        render_strength_bar(ui, strength);
    }

    ui.separator();

    if ui.button("Generate##gen") {
        state.form.password = Zeroizing::new(if state.generator.mode == GenMode::Passphrase {
            generate_passphrase(
                state.generator.word_count as usize,
                &state.generator.separator,
            )
        } else {
            generate_password(
                state.generator.length as usize,
                state.generator.uppercase,
                state.generator.lowercase,
                state.generator.numbers,
                state.generator.special,
                state.generator.ambiguous,
            )
        });
    }

    if state.modals.gen_from_add {
        ui.same_line();
        if ui.button("Use this##gen") {
            state.modals.gen_from_add = false;
            ui.close_current_popup();
        }

        ui.same_line();
        if ui.button("Cancel##gen") {
            state.form.password = Zeroizing::new(String::new());
            state.modals.gen_from_add = false;
            ui.close_current_popup();
        }
    } else {
        if ui.button("Copy to clipboard###gen") {
            let password = state.form.password.clone();
            state.copy_to_clipboard(&password, "generated password");
            ui.close_current_popup();
        }

        if ui.button("Close") {
            ui.close_current_popup();
        }
    }
}
