
  package digger

  # ================================================================================
  # ACCESS POLICY - Controls who can run which commands
  # ================================================================================

  # CRITICAL: Deny apply if there are any plan policy violations
  deny[msg] {
      input.action == "digger apply"
      count(input.planPolicyViolations) > 0
      msg := sprintf(
          "DENIED: Cannot apply because plan has %v policy violation(s): %v",
          [count(input.planPolicyViolations), input.planPolicyViolations]
      )
  }

  # Allow plan for everyone
  allow_command {
      input.action == "digger plan"
  }

  # Allow apply only if:
  # 1. No plan policy violations
  # 2. Approved by platform team
  allow_command {
      input.action == "digger apply"
      count(input.planPolicyViolations) == 0
      has_team_approval("platform", input.approval_teams)
  }

  # Allow apply for production projects only if:
  # 1. No plan policy violations
  # 2. Approved by both platform and security teams
  allow_command {
      input.action == "digger apply"
      contains(input.project, "prod")
      count(input.planPolicyViolations) == 0
      has_team_approval("platform", input.approval_teams)
      has_team_approval("security", input.approval_teams)
  }

  # Deny apply for production without proper approvals
  deny[msg] {
      input.action == "digger apply"
      contains(input.project, "prod")

      # Even if no plan violations, still need proper approvals
      count(input.planPolicyViolations) == 0

      platform_approved := has_team_approval("platform", input.approval_teams)
      security_approved := has_team_approval("security", input.approval_teams)

      not (platform_approved and security_approved)

      msg := sprintf(
          "DENIED: Production apply requires approval from BOTH 'platform' AND 'security' teams. Current approval
  teams: %v",
          [input.approval_teams]
      )
  }

  # Deny any action if there are unresolved plan violations
  deny[msg] {
      count(input.planPolicyViolations) > 0
      not input.action == "digger plan"  # Allow re-planning to fix violations
      msg := sprintf(
          "DENIED: Cannot proceed with '%v' - plan has %v violation(s) that must be resolved first: %v",
          [input.action, count(input.planPolicyViolations), input.planPolicyViolations]
      )
  }
