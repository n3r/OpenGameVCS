use std::{env, process::Command};

fn main() {
    let compiler = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(compiler)
        .arg("--version")
        .output()
        .expect("the selected Rust compiler must report its version");
    assert!(output.status.success(), "rustc --version failed");
    assert!(
        output.stderr.len() <= 256,
        "rustc version stderr is excessive"
    );
    assert!(
        output.stdout.len() <= 256,
        "rustc version output is excessive"
    );
    let raw = std::str::from_utf8(&output.stdout).expect("rustc version must be UTF-8");
    let version = raw.trim_end_matches(['\r', '\n']);
    assert!(
        version.starts_with("rustc ")
            && version.len() <= 192
            && !version.is_empty()
            && version
                .bytes()
                .all(|byte| byte == b' ' || byte.is_ascii_graphic()),
        "rustc returned an invalid version string"
    );
    println!("cargo:rustc-env=OGVCS_RUSTC_VERSION={version}");
    println!("cargo:rerun-if-env-changed=RUSTC");
}
