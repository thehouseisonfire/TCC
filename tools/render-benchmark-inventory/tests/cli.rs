use assert_cmd::Command;
use tempfile::tempdir;

#[test]
fn render_inventory_cli_reads_saved_terraform_output() -> anyhow::Result<()> {
    let temp = tempdir()?;
    let terraform_output = temp.path().join("terraform-output.json");
    std::fs::write(
        &terraform_output,
        r#"
{
  "ansible_inventory": {
    "sensitive": false,
    "type": [
      "object",
      {
        "ansible_host": "string",
        "ansible_user": "string",
        "host_alias": "string"
      }
    ],
    "value": {
      "host_alias": "tcc2-bench-host",
      "ansible_host": "203.0.113.20",
      "ansible_user": "benchmark"
    }
  }
}
"#
        .trim_start(),
    )?;

    let output = Command::cargo_bin("render-benchmark-inventory")?
        .arg("--terraform-json")
        .arg(&terraform_output)
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("\"tcc2-bench-host\":"));
    assert!(stdout.contains("ansible_host: \"203.0.113.20\""));
    assert!(stdout.contains("ansible_user: \"benchmark\""));

    Ok(())
}
