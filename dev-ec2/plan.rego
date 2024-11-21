package digger

deny[sprintf(message, [resource.address])] {
  message := "everything is denied %v"
  resource := input.terraform.resource_changes[_]
  true
}
