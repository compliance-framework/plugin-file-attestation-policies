package compliance_framework.critical_file_exists_test

import data.compliance_framework.critical_file_exists as policy

# Test: No file configured (no violation)
 test_no_file_no_violation if {
  inp := {}
  count(policy.violation) == 0 with input as inp
}

# Test: File missing triggers violation
 test_file_missing_violation if {
  inp := {
    "path": "PLAN.md",
    "exists": false,
    "attestation": null,
    "authorized_signers": ["tech-lead@company.com"],
  }
  violations := policy.violation with input as inp
  count(violations) == 1
  violations[{"id": "critical_file_missing", "remarks": "File is expected but does not exist in the provided path"}]
}

# Test: File exists, existence policy passes (no violation here)
 test_file_exists_no_violation if {
  inp := {
    "path": "PLAN.md",
    "exists": true,
    "attestation": null,
    "authorized_signers": ["tech-lead@company.com"],
  }
  count(policy.violation) == 0 with input as inp
}