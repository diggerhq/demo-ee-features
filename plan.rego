package digger

deny[sprintf("creation of EC2 instance %v is denied", [resource.address])] {
  resource := input.terraform.resource_changes[_]
  resource.type == "aws_instance"
  resource.change.actions[_] == "create"
}
