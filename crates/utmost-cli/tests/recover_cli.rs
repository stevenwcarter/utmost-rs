use assert_cmd::Command;

#[test]
fn recover_cli_accepts_candidates_flag() {
    let mut cmd = Command::cargo_bin("utmost").unwrap();
    cmd.args(["recover", "--help"]);
    let output = cmd.output().expect("run cli");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--candidates"),
        "help missing --candidates: {stdout}"
    );
}
