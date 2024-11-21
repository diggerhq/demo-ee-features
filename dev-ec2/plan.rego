package digger


import future.keywords.in

# Define required tags that must be present
required_tags = ["environment", "owner", "cost-center"]

# Extract all planned resources from newer Terraform format
resources[r] {
    r := input.terraform.resource_changes[_]
    r.change.actions[_] in ["create", "update"]
}

# Helper to get tags based on resource type
get_tags(resource) = tags {
    # AWS resources typically use tags directly
    tags := resource.change.after.tags
} else = tags {
    # Azure resources often use tags_all
    tags := resource.change.after.tags_all
} else = {} {
    true
}

# Main violation check
deny[msg] {
    r := resources[_]
    tags := get_tags(r)
    required_tag := required_tags[_]
    not tags[required_tag]
    
    msg := sprintf(
        "Resource %v (%v) is missing required tag: %v",
        [r.address, r.type, required_tag]
    )
}

# Empty tag check
deny[msg] {
    r := resources[_]
    tags := get_tags(r)
    required_tag := required_tags[_]
    tags[required_tag] == ""
    
    msg := sprintf(
        "Resource %v (%v) has empty value for tag: %v",
        [r.address, r.type, required_tag]
    )
}

# disallow ec2 instances
deny[msg] {
    r := resources[_]
    r.resource_type == "aws_instance"
    msg = "EC2 instances are not allowed in this environment"
}

# Summary of violations
violation_count = count(deny)

# Helper to check if violations exist
has_violations {
    count(deny) > 0
}
