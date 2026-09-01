use std::process;

const MAX_CODE_BYTES: usize = 96;
const MAX_RESULT_TEXT_BYTES: usize = 256;
const MAX_PLAIN_LOG_LINE_BYTES: usize = 384;
const SUCCESS_LABEL_BYTES: usize = "ok[".len();
const ERROR_LABEL_BYTES: usize = "error[".len();
const RESULT_LABEL_SUFFIX_BYTES: usize = "]: ".len();
const NEXT_STEP_LABEL_BYTES: usize = "Next step: ".len();

fn plain_code(value: &str) -> bool {
    value.len() >= 2
        && value.len() <= MAX_CODE_BYTES
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_uppercase() || (index > 0 && (byte.is_ascii_digit() || byte == b'_'))
        })
}

fn plain_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RESULT_TEXT_BYTES
        && value
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
}

fn human_outcome_is_safe(outcome: &ogvcs_local_cli::ProcessOutcome) -> bool {
    if !plain_code(&outcome.code)
        || !plain_text(&outcome.message)
        || !plain_text(&outcome.next_step)
    {
        return false;
    }
    let result_line_bytes = if outcome.ok {
        SUCCESS_LABEL_BYTES
    } else {
        ERROR_LABEL_BYTES
    } + outcome.code.len()
        + RESULT_LABEL_SUFFIX_BYTES
        + outcome.message.len();
    result_line_bytes <= MAX_PLAIN_LOG_LINE_BYTES
        && (outcome.ok
            || NEXT_STEP_LABEL_BYTES + outcome.next_step.len() <= MAX_PLAIN_LOG_LINE_BYTES)
}

fn main() {
    if ogvcs_local_cli::production::ProcessSignalCancellation::install().is_err() {
        eprintln!(
            "error[SIGNAL_HANDLER_UNAVAILABLE]: Recoverable cancellation could not be installed."
        );
        eprintln!("Next step: Retry in a supported terminal or console.");
        process::exit(7);
    }
    let outcome = ogvcs_local_cli::run_process(std::env::args().skip(1));
    let exit_code = outcome.exit_code;
    if outcome.machine {
        println!("{}", outcome.render_machine());
    } else if !human_outcome_is_safe(&outcome) {
        eprintln!(
            "error[INTERNAL_SERIALIZATION]: The candidate could not render a safe human result."
        );
        eprintln!("Next step: Retry with --format json and report the stable result code.");
        process::exit(ogvcs_local_cli::ExitClass::Internal.exit_code());
    } else if outcome.ok {
        println!("ok[{}]: {}", outcome.code, outcome.message);
    } else {
        eprintln!("error[{}]: {}", outcome.code, outcome.message);
        eprintln!("Next step: {}", outcome.next_step);
    }
    process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn outcome() -> ogvcs_local_cli::ProcessOutcome {
        ogvcs_local_cli::ProcessOutcome {
            machine: false,
            ok: false,
            exit_code: 6,
            code: "AUTHENTICATION_REQUIRED".to_owned(),
            message: "Authentication is required in noninteractive mode.".to_owned(),
            next_step: "Configure a supported credential provider before rerunning this command."
                .to_owned(),
            exit_class: ogvcs_local_cli::ExitClass::InteractionRequired,
            data: json!({}),
        }
    }

    #[test]
    fn human_result_guard_accepts_the_registered_plain_shape() {
        assert!(human_outcome_is_safe(&outcome()));
    }

    #[test]
    fn human_result_guard_rejects_controls_invalid_code_shapes_and_long_lines() {
        let mut candidate = outcome();
        candidate.message.push_str("\u{1b}[31m");
        assert!(!human_outcome_is_safe(&candidate));

        let mut candidate = outcome();
        candidate.message.push('\u{202e}');
        assert!(!human_outcome_is_safe(&candidate));

        let mut candidate = outcome();
        candidate.code = "NOT-REGISTERED".to_owned();
        assert!(!human_outcome_is_safe(&candidate));

        let mut candidate = outcome();
        candidate.code = "A".to_owned();
        assert!(!human_outcome_is_safe(&candidate));

        let mut candidate = outcome();
        candidate.next_step = "x".repeat(MAX_RESULT_TEXT_BYTES + 1);
        assert!(!human_outcome_is_safe(&candidate));
    }
}
