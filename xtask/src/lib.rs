use std::path::{Path, PathBuf};

pub mod benchmark_host_helper;
pub mod benchmark_host_smoke;
pub mod render_benchmark_inventory;

/// Return the repository root, assuming this crate lives at `<repo>/xtask`.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask crate should live directly under the repository root")
        .to_path_buf()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::process::Command;

    use regex::Regex;
    use serde_yaml::Value;

    use super::repo_root;

    fn read_text(path: &str) -> anyhow::Result<String> {
        Ok(std::fs::read_to_string(repo_root().join(path))?)
    }

    fn read_yaml(path: &str) -> anyhow::Result<Value> {
        Ok(serde_yaml::from_str(&read_text(path)?)?)
    }

    fn string_mapping(value: &Value) -> BTreeMap<String, String> {
        value
            .as_mapping()
            .expect("expected YAML mapping")
            .iter()
            .map(|(key, value)| {
                (
                    key.as_str().expect("expected string key").to_owned(),
                    value.as_str().expect("expected string value").to_owned(),
                )
            })
            .collect()
    }

    fn string_sequence(value: &Value) -> Vec<String> {
        value
            .as_sequence()
            .expect("expected YAML sequence")
            .iter()
            .map(|item| item.as_str().expect("expected string").to_owned())
            .collect()
    }

    #[test]
    fn benchmark_playbook_includes_benchmark_prereqs_role() -> anyhow::Result<()> {
        let payload = read_yaml("infra/ansible/playbook.yml")?;
        let roles = string_sequence(&payload[0]["roles"]);
        assert_eq!(
            roles,
            vec![
                "apt_snapshot".to_owned(),
                "base".to_owned(),
                "docker".to_owned(),
                "benchmark_prereqs".to_owned(),
            ]
        );
        Ok(())
    }

    #[test]
    fn benchmark_verify_playbook_covers_baseline_and_benchmark_roles() -> anyhow::Result<()> {
        let payload = read_yaml("infra/ansible/verify.yml")?;
        let roles = string_sequence(&payload[0]["roles"]);
        assert_eq!(
            roles,
            vec!["baseline_verify".to_owned(), "benchmark_verify".to_owned()]
        );
        Ok(())
    }

    #[test]
    fn benchmark_ansible_playbooks_pass_syntax_check() -> anyhow::Result<()> {
        let ansible_dir = repo_root().join("infra/ansible");

        for playbook_name in ["playbook.yml", "verify.yml"] {
            let output = Command::new("uv")
                .args([
                    "run",
                    "--locked",
                    "--group",
                    "dev",
                    "ansible-playbook",
                    "-i",
                    "inventory.example.yml",
                    playbook_name,
                    "--syntax-check",
                ])
                .current_dir(&ansible_dir)
                .output()?;

            assert!(
                output.status.success(),
                "ansible syntax check failed for {playbook_name}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }

        Ok(())
    }

    #[test]
    fn snapshot_id_and_package_locks_are_repo_pinned() -> anyhow::Result<()> {
        let benchmark_host_vars = read_yaml("infra/ansible/group_vars/all/benchmark_host.yml")?;
        let package_locks = read_yaml("infra/ansible/group_vars/all/package_locks.yml")?;

        let snapshot_id = benchmark_host_vars["benchmark_host_snapshot_id"]
            .as_str()
            .expect("snapshot id should be a string");
        assert!(Regex::new(r"^\d{8}T\d{6}Z$")?.is_match(snapshot_id));
        assert_eq!(
            benchmark_host_vars["benchmark_host_operator_user"]
                .as_str()
                .expect("operator user should be a string"),
            "benchmark"
        );

        assert_eq!(
            string_mapping(&package_locks["benchmark_host_base_package_versions"]),
            BTreeMap::from([
                ("ca-certificates".to_owned(), "20240203".to_owned()),
                ("curl".to_owned(), "8.5.0-2ubuntu10.3".to_owned()),
                ("git".to_owned(), "1:2.43.0-1ubuntu7.1".to_owned()),
                ("jq".to_owned(), "1.7.1-3build1".to_owned()),
            ])
        );
        assert_eq!(
            string_mapping(&package_locks["benchmark_host_docker_package_versions"]),
            BTreeMap::from([
                ("docker.io".to_owned(), "24.0.7-0ubuntu4.1".to_owned()),
                (
                    "docker-compose-v2".to_owned(),
                    "2.24.6+ds1-0ubuntu2".to_owned(),
                ),
            ])
        );

        Ok(())
    }

    #[test]
    fn benchmark_toolchain_pins_match_repo_contract() -> anyhow::Result<()> {
        let benchmark_toolchain =
            read_yaml("infra/ansible/group_vars/all/benchmark_toolchain.yml")?;
        let rust_toolchain: toml::Value = read_text("rust-toolchain.toml")?.parse()?;
        let python_version = read_text(".python-version")?.trim().to_owned();
        let benchmark_docs = read_text("mqtt-auth-biscuit/README.md")?;

        assert_eq!(
            benchmark_toolchain["benchmark_host_python_version"]
                .as_str()
                .expect("python version should be a string"),
            python_version
        );
        assert_eq!(
            benchmark_toolchain["benchmark_host_rust_toolchain"]
                .as_str()
                .expect("rust toolchain should be a string"),
            rust_toolchain["toolchain"]["channel"]
                .as_str()
                .expect("toolchain channel should be a string")
        );

        let yaml_components =
            string_sequence(&benchmark_toolchain["benchmark_host_rust_components"]);
        let toml_components = rust_toolchain["toolchain"]["components"]
            .as_array()
            .expect("toolchain components should be an array")
            .iter()
            .map(|item| {
                item.as_str()
                    .expect("component should be a string")
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(yaml_components, toml_components);

        assert_eq!(
            benchmark_toolchain["benchmark_host_uv_version"]
                .as_str()
                .expect("uv version should be a string"),
            "0.9.17"
        );
        assert!(benchmark_docs.contains("Python 3.14.2 + `uv 0.9.17`"));

        Ok(())
    }
}
