use crate::app::AppState;
use crate::modals::add_entry_from_inputs;

const AMEX_CARD_LEN: usize = 15;
const MIN_CARD_LEN: usize = 13;
const MAX_CARD_LEN: usize = 19;

pub const STANDARD_CVC_LEN: usize = 3;
pub const AMEX_CVC_LEN: usize = 4;

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

pub fn expected_cvc_len(number: &str) -> usize {
    if is_amex(number) {
        AMEX_CVC_LEN
    } else {
        STANDARD_CVC_LEN
    }
}

fn current_month_year() -> (u32, u32) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (secs / 86_400) as i64;

    // Civil date from days since the epoch (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    (year as u32, month as u32)
}

pub fn validate_expiry(expiry: &str) -> bool {
    let Some((month, _year)) = parse_expiry(expiry) else {
        return false;
    };
    (1..=12).contains(&month)
}

/// True when the card is still valid during the current month.
fn expiry_not_in_past(expiry: &str, now: (u32, u32)) -> bool {
    let Some((month, year)) = parse_expiry(expiry) else {
        return false;
    };
    let year = 2000 + year;
    year > now.0 || (year == now.0 && month >= now.1)
}

fn parse_expiry(expiry: &str) -> Option<(u32, u32)> {
    let expiry: String = expiry.chars().filter(|c| c.is_ascii_digit()).collect();
    if expiry.len() != EXPIRY_LEN {
        return None;
    }
    let month = expiry[..2].parse().ok()?;
    let year = expiry[2..].parse().ok()?;
    Some((month, year))
}

pub(crate) fn validate_card_fields(
    label: &str,
    number: &str,
    expiration_date: &str,
    cvc: &str,
    reject_expired: bool,
) -> Result<(), &'static str> {
    if label.trim().is_empty() {
        return Err("A label is required");
    }
    if number.is_empty() || expiration_date.is_empty() || cvc.is_empty() {
        return Err("Card details are required");
    }

    let valid_length = (MIN_CARD_LEN..=MAX_CARD_LEN).contains(&number.len());

    if !valid_length || !luhn_check(number) {
        return Err("Invalid card number");
    }

    if !validate_expiry(expiration_date) {
        return Err("Invalid expiration date (expected MMYY)");
    }
    // Only adding enforces freshness; editing an already-expired card
    // (e.g. correcting its label) must stay possible.
    if reject_expired && !expiry_not_in_past(expiration_date, current_month_year()) {
        return Err("Card expiration date is in the past");
    }

    if cvc.len() != expected_cvc_len(number) {
        return Err("Invalid CVC");
    }

    Ok(())
}

fn validate_card_form(state: &AppState) -> Result<(), &'static str> {
    validate_card_fields(
        state.form.label.as_str(),
        state.form.number.as_str(),
        state.form.expiration_date.as_str(),
        state.form.cvc.as_str(),
        true,
    )
}

pub fn render(ui: &imgui::Ui, state: &mut AppState) {
    ui.input_text("Label##card", &mut state.form.label).build();
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
        state.clear_inputs();
        ui.close_current_popup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_expiry_checks_format_and_month() {
        assert!(validate_expiry("1227"));
        assert!(validate_expiry("0130"));
        assert!(!validate_expiry("1327"));
        assert!(!validate_expiry("0027"));
        assert!(!validate_expiry("123"));
        assert!(!validate_expiry("12345"));
        assert!(!validate_expiry("abcd"));
    }

    #[test]
    fn expiry_not_in_past_compares_against_the_given_month() {
        let now = (2026, 10);
        assert!(expiry_not_in_past("1026", now));
        assert!(expiry_not_in_past("1126", now));
        assert!(expiry_not_in_past("0127", now));
        assert!(!expiry_not_in_past("0926", now));
        assert!(!expiry_not_in_past("1225", now));
        assert!(!expiry_not_in_past("bad", now));
    }
}
