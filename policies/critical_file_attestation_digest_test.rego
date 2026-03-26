package compliance_framework.critical_file_attestation_digest_test

import data.compliance_framework.critical_file_attestation_digest as policy

# Test: Attestation covers a different file version (digest mismatch, sha256)
 test_digest_mismatch_violation if {
  inp := {
    "path": "PLAN.md",
    "exists": true,
    "sha": "abc123currentsha",
    "attestation": {
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
  violations[{"id": "attestation_digest_mismatch", "remarks": "File has a digest mismatch between the repository content (sha=abc123currentsha) and the attestation subject digest (sha=def456oldsha)."}]
} 

# Test: Should fail if file does not exist
 test_digest_mismatch_violation if {
  inp := {
    "path": "PLAN.md",
    "exists": false,
    "sha": "abc123currentsha",
    "attestation": {
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
  violations[{"id": "attestation_digest_missing_tracked_file", "remarks": "Tracked file does not exist."}]
} 

# Test: Should fail if attestation file does not exist
 test_digest_mismatch_violation if {
  inp := {
    "path": "PLAN.md",
    "exists": true,
    "sha": "abc123currentsha",
    "attestation": {
      "path": "PLAN.md.bundle",
      "exists": false,
      "verified": false,
      "signer_identity": "tech-lead@company.com",
      "subject_digest_alg": "sha256",
      "subject_digest": "def456oldsha",
    },
    "authorized_signers": ["tech-lead@company.com"],
  }
  violations := policy.violation with input as inp
  count(violations) == 1
  # Check the actual remarks value using set indexing
  violations[{"id": "attestation_digest_missing", "remarks": "Attestation file does not exist."}]
} 

# Test: Should not fail if attestation path is not set
 test_digest_mismatch_violation if {
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
 test_digest_mismatch_violation if {
  inp := {
    "path": "PLAN.md",
    "exists": true,
    "sha": "abc123currentsha",
    "authorized_signers": ["tech-lead@company.com"],
  }
  violations := policy.violation with input as inp
  count(violations) == 0
} 
# Test: Matching digests - no violation
 test_digest_match_no_violation if {
  inp := {
    "path": "PLAN.md",
    "exists": true,
    "sha": "abc123samehash",
    "attestation": {
      "path": "PLAN.md.bundle",
      "exists": true,
      "verified": true,
      "signer_identity": "tech-lead@company.com",
      "subject_digest_alg": "sha256",
      "subject_digest": "abc123samehash",
    },
    "authorized_signers": ["tech-lead@company.com"],
  }
  count(policy.violation) == 0 with input as inp
}

# Test: Missing sha field - no digest mismatch violation (graceful handling)
 test_missing_sha_no_digest_violation if {
  inp := {
    "path": "PLAN.md",
    "exists": true,
    "attestation": {
      "path": "PLAN.md.bundle",
      "exists": true,
      "verified": true,
      "signer_identity": "tech-lead@company.com",
      "subject_digest": "def456oldsha",
    },
    "authorized_signers": ["tech-lead@company.com"],
  }
  # Should not trigger any violations (digest rule requires sha to be present)
  count(policy.violation) == 0 with input as inp
}

# Test: Missing subject_digest field - no digest mismatch violation (graceful handling)
 test_missing_subject_digest_no_violation if {
  inp := {
    "path": "PLAN.md",
    "exists": true,
    "sha": "abc123currentsha",
    "attestation": {
      "exists": true,
      "path": "PLAN.md.bundle",
      "verified": true,
      "signer_identity": "tech-lead@company.com",
    },
    "authorized_signers": ["tech-lead@company.com"],
  }
  # Should not trigger any violations (digest rule requires subject_digest to be present)
  count(policy.violation) == 0 with input as inp
}

test_risk_template_maps_digest_mismatch_violation_id if {
  templates := policy.risk_templates
  count(templates) == 1
  templates[_].violation_ids[_] == "attestation_digest_mismatch"
}
