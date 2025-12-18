 package digger

  deny[msg] {
      msg := sprintf("Plan Policy Input - User: %v", [input.user])
  }

  deny[msg] {
      msg := sprintf("Plan Policy Input - Organisation: %v", [input.organisation])
  }

  deny[msg] {
      msg := sprintf("Plan Policy Input - Project: %v", [input.project])
  }

  deny[msg] {
      msg := sprintf("Plan Policy Input - Teams: %v", [input.teams])
  }

  deny[msg] {
      msg := sprintf("Plan Policy Input - Approvals: %v", [input.approvals])
  }

  deny[msg] {
      msg := sprintf("Plan Policy Input - Terraform Plan Keys: %v", [object.keys(input.terraform)])
  }
