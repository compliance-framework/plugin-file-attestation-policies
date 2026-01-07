package compliance_framework.critical_file_attestation_signer_test

import data.compliance_framework.critical_file_attestation_signer as policy
# Test: Should fail if file does not exist
 test_fail_file_not_exists if {
  inp := {
    "path": "PLAN.md",
    "exists": false,
    "sha": "abc123currentsha",
    "attestation": {
      "path": "PLAN.md.bundle",
      "exists": true,
      "verified": true,
      "signer_identity": "tech-lead@company.com",
      "subject_digest_alg": "sha256",
      "subject_digest": "def456oldsha",
    },
    "authorized_signers": ["tech-lead@company.com"],
  }
  violations := policy.violation with input as inp
  count(violations) == 1
  # Check the actual remarks value using set indexing
  violations[{"remarks": "Tracked file does not exist."}]
} 

# Test: Should not fail if attestation path is not set
test_pass_if_no_attestation_path if {
  inp := {
    "path": "PLAN.md",
    "exists": true,
    "sha": "abc123currentsha",
    "attestation": {
      "path": "",
      "exists": false,
      "verified": false,
      "signer_identity": "tech-lead@company.com",
      "subject_digest_alg": "sha256",
      "subject_digest": "def456oldsha",
    },
    "authorized_signers": ["tech-lead@company.com"],
  }
  violations := policy.violation with input as inp
  count(violations) == 0
} 

# Test: Should not fail if attestation is not set
 test_pass_if_no_attestation if {
  inp := {
    "path": "PLAN.md",
    "exists": true,
    "sha": "abc123currentsha",
    "authorized_signers": ["tech-lead@company.com"],
  }
  violations := policy.violation with input as inp
  count(violations) == 0
} 

# Test: File exists but attestation does not exist (exists=false)
 test_file_exists_attestation_not_exists_violation if {
  inp := {
    "path": "SECURITY.md",
    "exists": true,
    "attestation": {"path": "SECURITY.md.bundle", "exists": false},
    "authorized_signers": ["security@company.com"],
  }
  violation := policy.violation with input as inp
  count(violation) == 1
  violation[{"remarks": "Attestation for tracked file does not exist."}]
}

# Test: Attestation exists but not verified
 test_attestation_not_verified_violation if {
  inp := {
    "path": "PLAN.md",
    "exists": true,
    "attestation": {
            "path": "PLAN.md.bundle",
      "exists": true,
      "verified": false,
      "error": "signature mismatch",
    },
    "authorized_signers": ["tech-lead@company.com"],
  }
  
  violation := policy.violation with input as inp
  count(violation) == 1
  violation[{"remarks": "File has an attestation with an invalid or unverified signature."}]
}

# Test: Attestation verified but signer not authorized
 test_unauthorized_signer_violation if {
  inp := {
    "path": "PLAN.md",
    "exists": true,
    "attestation": {
      "path": "PLAN.md.bundle",
      "exists": true,
      "verified": true,
      "signer_identity": "random@attacker.com",
    },
    "authorized_signers": ["tech-lead@company.com", "cto@company.com"],
  }
  violations := policy.violation with input as inp

  count(violations) == 1
  violations[{"remarks": "File has a verified attestation signed by an unauthorized signer (random@attacker.com)."}]

}

# Test: Valid attestation with authorized signer (no violation)
 test_valid_attestation_no_violation if {
  inp := {
    "path": "PLAN.md",
    "exists": true,
    "attestation": {
      "path": "PLAN.md.bundle",
      "exists": true,
      "verified": true,
      "signer_identity": "tech-lead@company.com",
    },
    "authorized_signers": ["tech-lead@company.com", "cto@company.com"],
  }
  count(policy.violation) == 0 with input as inp
}
