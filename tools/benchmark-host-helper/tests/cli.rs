use assert_cmd::Command;
use serde_json::Value;

#[test]
fn benchmark_host_helper_json_cli_reports_expected_layout() -> anyhow::Result<()> {
    let output = Command::cargo_bin("benchmark-host-helper")?
        .arg("--json")
        .output()?;

    assert!(output.status.success());
    let payload: Value = serde_json::from_slice(&output.stdout)?;
    let relative_layout = &payload["relative_layout"];

    assert_eq!(relative_layout["terraform_root"], "infra/terraform");
    assert_eq!(relative_layout["ansible_root"], "infra/ansible");
    assert_eq!(relative_layout["infra_readme_path"], "infra/README.md");
    assert_eq!(relative_layout["todo_path"], "TODO2.md");
    assert_eq!(
        payload["recommended_stack"],
        serde_json::json!(["terraform", "ansible", "apt-snapshots"])
    );
    assert_eq!(payload["packer_stage"], "deferred");

    Ok(())
}
