mock_provider "hcloud" {
  override_during = plan
}

variables {
  location                = "fsn1"
  server_type             = "cpx21"
  operator_ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEBENCHMARKPUBLICKEY benchmark@example"
  allowed_ssh_cidrs       = ["203.0.113.10/32"]
}

run "keeps_default_labels_without_custom_input" {
  command = plan

  assert {
    condition = tomap(hcloud_ssh_key.operator.labels) == tomap({
      "managed-by" = "terraform"
      "repo"       = "TCC2"
      "role"       = "benchmark-host"
    })
    error_message = "SSH key labels should keep the built-in defaults when labels is unset."
  }

  assert {
    condition = tomap(hcloud_firewall.benchmark.labels) == tomap({
      "managed-by" = "terraform"
      "repo"       = "TCC2"
      "role"       = "benchmark-host"
    })
    error_message = "Firewall labels should keep the built-in defaults when labels is unset."
  }

  assert {
    condition = tomap(hcloud_server.benchmark.labels) == tomap({
      "managed-by" = "terraform"
      "repo"       = "TCC2"
      "role"       = "benchmark-host"
    })
    error_message = "Server labels should keep the built-in defaults when labels is unset."
  }
}

run "merges_custom_labels_with_defaults" {
  command = plan

  variables {
    labels = {
      "environment" = "benchmark"
    }
  }

  assert {
    condition = tomap(hcloud_server.benchmark.labels) == tomap({
      "environment" = "benchmark"
      "managed-by"  = "terraform"
      "repo"        = "TCC2"
      "role"        = "benchmark-host"
    })
    error_message = "Custom labels should be merged with built-in defaults."
  }
}

run "treats_null_labels_as_no_extra_labels" {
  command = plan

  variables {
    labels = null
  }

  assert {
    condition = tomap(hcloud_server.benchmark.labels) == tomap({
      "managed-by" = "terraform"
      "repo"       = "TCC2"
      "role"       = "benchmark-host"
    })
    error_message = "Null labels should behave the same as omitting the labels input."
  }
}

run "caller_overrides_default_label_values" {
  command = plan

  variables {
    labels = {
      "managed-by" = "custom-automation"
      "team"       = "perf"
    }
  }

  assert {
    condition = tomap(hcloud_server.benchmark.labels) == tomap({
      "managed-by" = "custom-automation"
      "repo"       = "TCC2"
      "role"       = "benchmark-host"
      "team"       = "perf"
    })
    error_message = "Caller labels should override built-in keys and preserve the remaining defaults."
  }
}
