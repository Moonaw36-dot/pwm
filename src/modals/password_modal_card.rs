use crate::app::AppState;
use crate::modals::add_entry_from_inputs;
use crate::strength::get_card_issuer;

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
    if ui.input_text("Card number", &mut *state.form.number)
        .password(true)
        .chars_decimal(true)
        .build()
    {
        state.form.number.truncate(19);
    }

    let card = state.form.number.as_str();
    if !card.is_empty() {
        let issuer = get_card_issuer(card);
        ui.text_colored([0.5, 0.5, 0.5, 1.0], issuer);

        let valid = luhn_check(card);
        if valid {
            ui.text_colored([0.0, 0.8, 0.0, 1.0], "Valid");
        } else if card.len() >= 13 {
            ui.text_colored([0.8, 0.0, 0.0, 1.0], "Invalid");
        }
    }
    
    if ui.input_text("Expiry date", &mut state.form.expiration_date)
        .chars_decimal(true)
        .build()
    {
        let mut digits: String = state.form.expiration_date.chars().filter(|c| c.is_ascii_digit()).collect();
        digits.truncate(4);
        if digits.len() >= 3 {
            state.form.expiration_date = format!("{}/{}", &digits[..2], &digits[2..]).into();
        } else {
            state.form.expiration_date = digits.into();
        }
    }

    if ui.input_text("CVC", &mut state.form.cvc)
        .chars_decimal(true)
        .build()
    {
        state.form.cvc.truncate(4);
    }

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