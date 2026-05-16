use crate::app::AppState;
use crate::modals::add_entry_from_inputs;

const STANDARD_CARD_LEN: usize = 16;
const AMEX_CARD_LEN: usize = 15;

const STANDARD_CVC_LEN: usize = 3;
const AMEX_CVC_LEN: usize = 4;

const EXPIRY_LEN: usize = 4;

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

fn is_amex(number: &str) -> bool {
    number.len() == AMEX_CARD_LEN
}

fn expected_cvc_len(number: &str) -> usize {
    if is_amex(number) {
        AMEX_CVC_LEN
    } else {
        STANDARD_CVC_LEN
    }
}

fn validate_expiry(expiry: &str) -> bool {
    if expiry.len() != EXPIRY_LEN {
        return false;
    }
    let month: u32 = match expiry[..2].parse() {
        Ok(m) => m,
        Err(_) => return false,
    };
    let year: u32 = match expiry[2..].parse() {
        Ok(y) => y,
        Err(_) => return false,
    };
    // Month must be 01–12, year must be a valid 2-digit year
    month >= 1 && month <= 12 && year <= 99
}

fn validate_card_form(state: &mut AppState) -> Result<(), &'static str> {
    if state.form.number.is_empty()
        || state.form.expiration_date.is_empty()
        || state.form.cvc.is_empty()
    {
        return Err("Card details are required");
    }

    let valid_length =
        state.form.number.len() == STANDARD_CARD_LEN || state.form.number.len() == AMEX_CARD_LEN;

    if !valid_length || !luhn_check(state.form.number.as_str()) {
        return Err("Invalid card number");
    }

    if !validate_expiry(state.form.expiration_date.as_str()) {
        return Err("Invalid expiration date (expected MMYY)");
    }

    if state.form.cvc.len() != expected_cvc_len(state.form.number.as_str()) {
        return Err("Invalid CVC");
    }

    Ok(())
}

pub fn render(ui: &imgui::Ui, state: &mut AppState) {
    crate::modals::render_card_fields(ui, state);

    if ui.button("Save") {
        match validate_card_form(state) {
            Ok(()) => {
                add_entry_from_inputs(state);
                state.clear_inputs();
                ui.close_current_popup();
            }
            Err(msg) => {
                state.custom_error_message = Some(msg.to_string());
            }
        }
    }

    ui.same_line();
    if ui.button("Close") {
        ui.close_current_popup();
    }
}
