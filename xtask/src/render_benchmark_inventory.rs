use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::repo_root;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InventoryHost {
    pub host_alias: String,
    pub ansible_host: String,
    pub ansible_user: String,
}

fn extract_string(candidate: &Value, key: &str) -> Result<String> {
    let value = candidate
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing required string field: {key}"))?
        .trim()
        .to_owned();

    if value.is_empty() {
        bail!("Terraform ansible_inventory fields must not be empty.");
    }

    Ok(value)
}

pub fn extract_inventory_host(payload: Value) -> Result<InventoryHost> {
    let candidate = payload
        .get("ansible_inventory")
        .map(|inventory| inventory.get("value").unwrap_or(inventory))
        .unwrap_or(&payload);

    if !candidate.is_object() {
        bail!("Terraform output did not contain an ansible_inventory object.");
    }

    let missing = ["host_alias", "ansible_host", "ansible_user"]
        .into_iter()
        .filter(|key| !candidate.get(key).is_some_and(Value::is_string))
        .collect::<Vec<_>>();

    if !missing.is_empty() {
        bail!(
            "Terraform ansible_inventory is missing required string fields: {}",
            missing.join(", ")
        );
    }

    Ok(InventoryHost {
        host_alias: extract_string(candidate, "host_alias")?,
        ansible_host: extract_string(candidate, "ansible_host")?,
        ansible_user: extract_string(candidate, "ansible_user")?,
    })
}

pub fn load_inventory_from_json_file(json_path: &Path) -> Result<InventoryHost> {
    let text = std::fs::read_to_string(json_path)
        .with_context(|| format!("failed to read {}", json_path.display()))?;
    let payload = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse JSON from {}", json_path.display()))?;
    extract_inventory_host(payload)
}

pub fn load_inventory_from_terraform() -> Result<InventoryHost> {
    let terraform_dir = repo_root().join("infra/terraform");
    let output = Command::new("terraform")
        .arg(format!("-chdir={}", terraform_dir.display()))
        .args(["output", "-json"])
        .output()
        .context("failed to run terraform output -json")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "terraform output -json exited with {}: {}",
            output.status,
            stderr.trim()
        );
    }

    let payload =
        serde_json::from_slice(&output.stdout).context("terraform emitted invalid JSON")?;
    extract_inventory_host(payload)
}

pub fn render_inventory_yaml(inventory_host: &InventoryHost) -> Result<String> {
    let host_alias = serde_json::to_string(&inventory_host.host_alias)?;
    let ansible_host = serde_json::to_string(&inventory_host.ansible_host)?;
    let ansible_user = serde_json::to_string(&inventory_host.ansible_user)?;

    Ok([
        "---".to_owned(),
        "all:".to_owned(),
        "  hosts:".to_owned(),
        format!("    {host_alias}:"),
        format!("      ansible_host: {ansible_host}"),
        format!("      ansible_user: {ansible_user}"),
        String::new(),
    ]
    .join("\n"))
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum InventorySource {
    Terraform,
    JsonFile(PathBuf),
}

pub fn load_inventory(source: &InventorySource) -> Result<InventoryHost> {
    match source {
        InventorySource::Terraform => load_inventory_from_terraform(),
        InventorySource::JsonFile(path) => load_inventory_from_json_file(path),
    }
}

#[cfg(test)]
mod tests {
    use super::{InventoryHost, load_inventory_from_json_file, render_inventory_yaml};

    #[test]
    fn render_inventory_yaml_uses_structured_inventory_fields() -> anyhow::Result<()> {
        let rendered = render_inventory_yaml(&InventoryHost {
            host_alias: "tcc2-bench-host".to_owned(),
            ansible_host: "198.51.100.10".to_owned(),
            ansible_user: "benchmark".to_owned(),
        })?;

        assert!(rendered.contains("\"tcc2-bench-host\":"));
        assert!(rendered.contains("ansible_host: \"198.51.100.10\""));
        assert!(rendered.contains("ansible_user: \"benchmark\""));

        Ok(())
    }

    #[test]
    fn load_inventory_json_reads_saved_terraform_output() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
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

        let host = load_inventory_from_json_file(&terraform_output)?;

        assert_eq!(host.host_alias, "tcc2-bench-host");
        assert_eq!(host.ansible_host, "203.0.113.20");
        assert_eq!(host.ansible_user, "benchmark");

        Ok(())
    }
}
