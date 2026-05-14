use serde::Serialize;

use crate::repo_root;

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct RelativeLayout {
    // Keep this declaration order aligned with Python's json.dumps(sort_keys=True).
    pub ansible_root: &'static str,
    pub infra_readme_path: &'static str,
    pub infra_root: &'static str,
    pub terraform_root: &'static str,
    pub todo_path: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct TargetInfo {
    // Keep this declaration order aligned with Python's json.dumps(sort_keys=True).
    pub os: &'static str,
    pub provider: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct BenchmarkHostPaths {
    // Keep this declaration order aligned with Python's json.dumps(sort_keys=True).
    pub packer_stage: &'static str,
    pub recommended_stack: [&'static str; 3],
    pub relative_layout: RelativeLayout,
    pub repo_root: String,
    pub target: TargetInfo,
}

pub fn benchmark_host_paths() -> BenchmarkHostPaths {
    BenchmarkHostPaths {
        packer_stage: "deferred",
        recommended_stack: ["terraform", "ansible", "apt-snapshots"],
        relative_layout: RelativeLayout {
            ansible_root: "infra/ansible",
            infra_readme_path: "infra/README.md",
            infra_root: "infra",
            terraform_root: "infra/terraform",
            todo_path: "TODO2.md",
        },
        repo_root: repo_root().display().to_string(),
        target: TargetInfo {
            os: "ubuntu-24.04",
            provider: "hetzner",
        },
    }
}

pub fn render_human(payload: &BenchmarkHostPaths) -> String {
    let layout = &payload.relative_layout;
    let target = &payload.target;

    [
        format!("repo_root: {}", payload.repo_root),
        format!("infra_root: {}", layout.infra_root),
        format!("terraform_root: {}", layout.terraform_root),
        format!("ansible_root: {}", layout.ansible_root),
        format!("infra_readme_path: {}", layout.infra_readme_path),
        format!("todo_path: {}", layout.todo_path),
        format!(
            "recommended_stack: {}",
            payload.recommended_stack.join(", ")
        ),
        format!("packer_stage: {}", payload.packer_stage),
        format!("target_provider: {}", target.provider),
        format!("target_os: {}", target.os),
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::benchmark_host_paths;
    use crate::repo_root;

    #[test]
    fn benchmark_host_helper_returns_canonical_paths() {
        let payload = benchmark_host_paths();

        assert_eq!(payload.repo_root, repo_root().display().to_string());
        assert_eq!(payload.relative_layout.infra_root, "infra");
        assert_eq!(payload.relative_layout.terraform_root, "infra/terraform");
        assert_eq!(payload.relative_layout.ansible_root, "infra/ansible");
        assert_eq!(payload.relative_layout.infra_readme_path, "infra/README.md");
        assert_eq!(payload.relative_layout.todo_path, "TODO2.md");
        assert_eq!(
            payload.recommended_stack,
            ["terraform", "ansible", "apt-snapshots"]
        );
        assert_eq!(payload.packer_stage, "deferred");
        assert_eq!(payload.target.provider, "hetzner");
        assert_eq!(payload.target.os, "ubuntu-24.04");
    }
}
