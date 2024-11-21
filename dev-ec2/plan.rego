package digger

# Define required tags that must be present
required_tags = ["environment", "owner", "cost-center"]

# Get all resources that support tags
resources[r] {
    r := input.terraform.root_module.resources[_]
}

# Deny if any required tags are missing
deny[msg] {
    r := resources[_]
    required_tag := required_tags[_]
    not r.values.tags[required_tag]
    msg := sprintf(
        "Resource %v of type %v is missing required tag: %v",
        [r.address, r.type, required_tag]
    )
}

# Ensure tags are not empty strings
deny[msg] {
    r := resources[_]
    required_tag := required_tags[_]
    r.values.tags[required_tag] == ""
    msg := sprintf(
        "Resource %v of type %v has empty value for tag: %v",
        [r.address, r.type, required_tag]
    )
}

# Helper to count violations
violation_count = count(deny)
