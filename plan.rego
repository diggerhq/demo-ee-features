package digger

deny[sprintf(message, [resource.address])] {
  message := "everything is allowed %v"
  resource := input.terraform.resource_changes[_]
  false
}
