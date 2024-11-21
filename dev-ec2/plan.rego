package digger

deny[sprintf(message, [resource.address])] {
  message := "everything is allowed"
  resource := input.terraform.resource_changes[_]
  true
}
