use crate::app::AppState;
use crate::modals::add_entry_from_inputs;

pub fn luhn_check(card: &str) -> bool {
    let mut sum = 0;
    let mut alternate = false;
    for ch in card.chars().rev() {
        let d = match ch.to_digit(10) {
            Some(d) => d,
            None => return false,
        };
        if alternate {
            let doubled = d * 2;
            sum += if doubled > 9 { doubled - 9 } else { doubled };
        } else {
            sum += d;
        }
        alternate = !alternate;
    }
    sum % 10 == 0
}

pub fn render(ui: &imgui::Ui, state: &mut AppState) {
    crate::modals::render_card_fields(ui, state);

    if ui.button("Close") {
        ui.close_current_popup();
    }

    ui.same_line();

    if ui.button("Save") {
        add_entry_from_inputs(state);
        state.clear_inputs();
        ui.close_current_popup()
    }
    

    
}