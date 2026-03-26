package compliance_framework.critical_file_attestation_digest

# Policy: ensure the attestation's recorded digest matches the file's digest
# for all supported algorithms (sha256, sha512).

default has_tracked_file := false

risk_templates := [{
  "name": "Critical artifact attestation digest mismatch",
  "title": "Artifact Attestation Digest Mismatch",
  "statement": "The attestation for the tracked critical artifact records a digest that does not match the artifact's current digest in the repository. This weakens integrity and provenance assurances because the attestation may describe different content than what is actually present, preventing reliable trust in the artifact and its supply-chain evidence.",
  "likelihood_hint": "medium",
  "impact_hint": "high",
  "violation_ids": ["attestation_digest_mismatch"],
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-354",
      "title": "Improper Validation of Integrity Check Value",
      "url": "https://cwe.mitre.org/data/definitions/354.html"
    }
  ],
  "remediation": {
    "title": "Reconcile attestation digest with repository content",
    "description": "Ensure the attestation and repository artifact refer to the same content version and that digest verification is performed against the correct algorithm and artifact instance.",
    "tasks": [
      { "title": "Confirm the tracked artifact path and expected digest algorithm" },
      { "title": "Verify the repository artifact and the attested subject refer to the same content version" },
      { "title": "Regenerate or restore the attestation from the approved build or signing workflow if the artifact changed intentionally" },
      { "title": "Investigate unexpected digest changes for tampering, drift, or release-process errors" },
    ]
  }
}]

has_tracked_file if {
  input.path != ""
}
# Helper: collect all digest mismatch messages across supported algorithms.
digest_mismatch[msg] if {
  has_tracked_file
  input.exists
  input.attestation != null
  input.attestation.exists
  input.attestation.verified
  lower(input.attestation.subject_digest_alg) == "sha256"
  input.sha != ""
  input.attestation.subject_digest != ""
  input.sha != input.attestation.subject_digest
  msg := sprintf(
    "File has a digest mismatch between the repository content (sha=%v) and the attestation subject digest (sha=%v).",
    [input.sha, input.attestation.subject_digest],
  )
}

digest_mismatch[msg] if {
  has_tracked_file
  input.exists
  input.attestation != null
  input.attestation.exists
  input.attestation.verified
  lower(input.attestation.subject_digest_alg) == "sha512"
  input.sha512 != ""
  input.attestation.subject_digest != ""
  input.sha512 != input.attestation.subject_digest
  msg := sprintf(
    "File has a digest mismatch between the repository content (sha512=%v) and the attestation subject digest (sha512=%v).",
    [input.sha512, input.attestation.subject_digest],
  )
}

violation[{"id": "attestation_digest_missing_tracked_file", "remarks": "Tracked file does not exist."}] if {
  has_tracked_file
  not input.exists
}

violation[{"id": "attestation_digest_missing", "remarks": "Attestation file does not exist."}] if {
  input.attestation.path != ""
  not input.attestation.exists
}

violation[{"id": "attestation_digest_mismatch", "remarks": msg}] if {
  digest_mismatch[msg]
}

title := "File attestation digest matches repository content"

description := "The digest recorded in the attestation for the tracked file must match the file's current digest in the repository for all supported hash algorithms."
