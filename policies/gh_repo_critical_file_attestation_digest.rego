package compliance_framework.critical_file_attestation_digest

# Policy: ensure the attestation's recorded digest matches the file's digest
# for all supported algorithms (sha256, sha512).

default has_tracked_file := false

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

violation[{"remarks": "Tracked file does not exist."}] if {
  has_tracked_file
  not input.exists
}

violation[{"remarks": "Attestation file does not exist."}] if {
  input.attestation.path != ""
  not input.attestation.exists
}

violation[{"remarks": msg}] if {
  digest_mismatch[msg]
}

title := "File attestation digest matches repository content"

description := "The digest recorded in the attestation for the tracked file must match the file's current digest in the repository for all supported hash algorithms."
