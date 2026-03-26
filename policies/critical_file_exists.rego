package compliance_framework.critical_file_exists

# Policy: ensure the tracked critical file exists in the repository.

default has_tracked_file := false

risk_templates := [{
  "name": "Tracked critical artifact missing",
  "title": "Missing Critical Artifact",
  "statement": "A tracked critical artifact expected to be present is missing. When a required security-sensitive artifact, deployment file, or control evidence file is absent, integrity assurance and traceability are weakened and required controls may not be enforceable or auditable.",
  "likelihood_hint": "medium",
  "impact_hint": "high",
  "violation_ids": ["critical_file_missing"],
  "threat_refs": [],
  "remediation": {
    "title": "Restore and protect the tracked critical artifact",
    "description": "Ensure the expected artifact exists at the configured path and is maintained through approved change control so integrity and attestation checks can be performed reliably.",
    "tasks": [
      { "title": "Confirm the expected path and filename for the tracked critical artifact" },
      { "title": "Restore or commit the missing artifact from an approved source or baseline" },
      { "title": "Review recent changes to determine whether the artifact was removed unintentionally or without approval" },
      { "title": "Add guardrails so required artifacts cannot be removed silently" },
    ]
  }
}]

has_tracked_file if {
  input.path != ""
}

violation[{"id": "critical_file_missing", "remarks": "File is expected but does not exist in the provided path"}] if {
  has_tracked_file
  not input.exists
}

title := "File exists"

description := "The tracked file must exist in the provided path."
