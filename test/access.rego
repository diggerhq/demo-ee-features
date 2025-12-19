  package digger

  # ================================================================================
  # ACCESS POLICY - Controls who can run which commands
  # ================================================================================

  # ================================================================================
  # HELPER FUNCTIONS - Define these first
  # ================================================================================

  # Check if a specific team is in the approval teams list
  has_team_approval(required_team, approval_teams) {
      some team in approval_teams
      team == required_team
  }

  # Check if user is in a specific team
  user_in_team(team_name) {
      some team in input.teams
      team == team_name
  }

  # Check if plan contains sensitive resource changes
  has_sensitive_changes(plan_output) {
      some resource in sensitive_resources
      contains(plan_output, resource)
  }

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

  # Allow apply only if no plan policy violations and approved by platform team
  allow_command {
      input.action == "digger apply"
      count(input.planPolicyViolations) == 0
      has_team_approval("platform", input.approval_teams)
  }

  # Allow apply for production projects with no violations and both team approvals
  allow_command {
      input.action == "digger apply"
      contains(input.project, "prod")
      count(input.planPolicyViolations) == 0
      has_team_approval("platform", input.approval_teams)
      has_team_approval("security", input.approval_teams)
  }

  # Deny apply for production without platform approval
  deny[msg] {
      input.action == "digger apply"
      contains(input.project, "prod")
      count(input.planPolicyViolations) == 0
      not has_team_approval("platform", input.approval_teams)

      msg := sprintf(
          "DENIED: Production apply requires approval from 'platform' team. Current approval teams: %v",
          [input.approval_teams]
      )
  }

  # Deny apply for production without security approval
  deny[msg] {
      input.action == "digger apply"
      contains(input.project, "prod")
      count(input.planPolicyViolations) == 0
      not has_team_approval("security", input.approval_teams)

      msg := sprintf(
          "DENIED: Production apply requires approval from 'security' team. Current approval teams: %v",
          [input.approval_teams]
      )
  }

  # Deny any action (except plan) if there are unresolved plan violations
  deny[msg] {
      count(input.planPolicyViolations) > 0
      not input.action == "digger plan"
      msg := sprintf(
          "DENIED: Cannot proceed with '%v' - plan has %v violation(s) that must be resolved first: %v",
          [input.action, count(input.planPolicyViolations), input.planPolicyViolations]
      )
  }
