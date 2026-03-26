package compliance_framework.critical_file_attestation_signer

# Policy: ensure that if the tracked critical file exists, it has an attestation
# that exists, is verified, and is signed by an authorized signer.

default has_tracked_file := false

risk_templates := [
  {
    "name": "Critical file attestation signature invalid or unverified",
    "title": "Untrusted Artifact Attestation Signature",
    "statement": "The attestation for the tracked critical artifact is present but its signature is invalid or unverified. This means the attestation's authenticity cannot be relied on and untrusted or tampered provenance data may be accepted or acted upon.",
    "likelihood_hint": "medium",
    "impact_hint": "high",
    "violation_ids": ["attestation_signature_unverified"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-347",
        "title": "Improper Verification of Cryptographic Signature",
        "url": "https://cwe.mitre.org/data/definitions/347.html"
      }
    ],
    "remediation": {
      "title": "Restore trusted signature verification for the attestation",
      "description": "Ensure the attestation is signed correctly and that verification is performed against the intended trust anchors and verification policy.",
      "tasks": [
        { "title": "Confirm the attestation was signed by the expected signing workflow" },
        { "title": "Validate the verifier configuration, trust roots, and identity constraints" },
        { "title": "Re-issue the attestation if the signature is invalid, expired, or malformed" },
      ]
    }
  },
  {
    "name": "Critical file attestation signer not authorized",
    "title": "Artifact Attestation Signed by Unapproved Identity",
    "statement": "The attestation for the tracked critical artifact is cryptographically valid but was signed by an identity outside the configured authorized signer set. This weakens provenance governance and can allow unapproved build or release identities to assert trust over critical artifacts.",
    "likelihood_hint": "medium",
    "impact_hint": "high",
    "violation_ids": ["attestation_unauthorized_signer"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-346",
        "title": "Origin Validation Error",
        "url": "https://cwe.mitre.org/data/definitions/346.html"
      }
    ],
    "remediation": {
      "title": "Restrict trust to approved attestation signers",
      "description": "Align signer authorization policy with approved build and release identities and reject attestations signed by identities outside that trust boundary.",
      "tasks": [
        { "title": "Review the authorized signer list for the tracked artifact" },
        { "title": "Confirm the attestation signer identity belongs to an approved build or release principal" },
        { "title": "Update signing workflows or authorization policy so only approved identities can sign" },
        { "title": "Re-issue the attestation with an approved signer if necessary" }
      ]
    }
  }
]

has_tracked_file if {
  input.path != ""
}

attestation_failure[{"id": "attestation_missing", "remarks": "Attestation for tracked file does not exist."}] if {
  has_tracked_file
  input.exists
  input.attestation != null
  input.attestation.path != ""
  not input.attestation.exists
}

attestation_failure[{"id": "attestation_signature_unverified", "remarks": "File has an attestation with an invalid or unverified signature."}] if {
  has_tracked_file
  input.exists
  input.attestation != null
  input.attestation.path != ""
  input.attestation.exists
  not input.attestation.verified
}

attestation_failure[{"id": "attestation_unauthorized_signer", "remarks": msg}] if {
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
violation[{"id": "attestation_signer_missing_tracked_file", "remarks": "Tracked file does not exist."}] if {
  has_tracked_file
  not input.exists
}


violation[entry] if {
  attestation_failure[entry]
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
