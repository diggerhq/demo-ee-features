
  package digger

  # Allow all for testing, but log what we receive
  default allow = false

  allow {
      # Print inputs by checking conditions that log the values
      trace(sprintf("Access Policy Input - User: %v", [input.user]))
      trace(sprintf("Access Policy Input - Organisation: %v", [input.organisation]))
      trace(sprintf("Access Policy Input - Project: %v", [input.project]))
      trace(sprintf("Access Policy Input - Action: %v", [input.action]))
      trace(sprintf("Access Policy Input - Teams: %v", [input.teams]))
      trace(sprintf("Access Policy Input - Approvals: %v", [input.approvals]))
      trace(sprintf("Access Policy Input - Plan Policy Violations: %v", [input.planPolicyViolations]))

      # Always allow for testing
      true
  }
