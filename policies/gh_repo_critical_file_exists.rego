package compliance_framework.critical_file_exists

# Policy: ensure the tracked critical file exists in the repository.

default has_tracked_file := false

has_tracked_file if {
  input.path != ""
}

violation[{"remarks": "File is expected but does not exist in the provided path"}] if {
  has_tracked_file
  not input.exists
}

title := "File exists"

description := "The tracked file must exist in the provided path."
