package compliance_framework.critical_file_attestation_signer

# Policy: ensure that if the tracked critical file exists, it has an attestation
# that exists, is verified, and is signed by an authorized signer.

default has_tracked_file := false

has_tracked_file if {
  input.path != ""
}

attestation_failure[msg] if {
  has_tracked_file
  input.exists
  input.attestation != null
  input.attestation.path != ""
  not input.attestation.exists
  msg := "Attestation for tracked file does not exist."
}

attestation_failure[msg] if {
  has_tracked_file
  input.exists
  input.attestation != null
  input.attestation.path != ""
  input.attestation.exists
  not input.attestation.verified
  msg := "File has an attestation with an invalid or unverified signature."
}

attestation_failure[msg] if {
  has_tracked_file
  input.exists
  input.attestation != null
  input.attestation.path != ""
  input.attestation.exists
  input.attestation.verified
  count(input.authorized_signers) > 0
  not signer_authorized(input.attestation.signer_identity, input.authorized_signers)
  msg := sprintf("File has a verified attestation signed by an unauthorized signer (%v).", [input.attestation.signer_identity])
}
violation[{"remarks": "Tracked file does not exist."}] if {
  has_tracked_file
  not input.exists
}


violation[{"remarks": msg}] if {
  attestation_failure[msg]
}

signer_authorized(signer, authorized) if {
  some auth in authorized
  signer == auth
}

signer_authorized(signer, authorized) if {
  some auth in authorized
  contains(signer, auth)
}

title := "File has valid attestation and authorized signer"

description := "The tracked file must have an existing, verified attestation signed by one of the configured authorized signers."