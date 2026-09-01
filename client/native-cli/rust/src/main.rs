use std::process;

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
    } else if outcome.ok {
        println!("ok[{}]: {}", outcome.code, outcome.message);
    } else {
        eprintln!("error[{}]: {}", outcome.code, outcome.message);
        eprintln!("Next step: {}", outcome.next_step);
    }
    process::exit(exit_code);
}
