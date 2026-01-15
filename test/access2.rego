
  package digger

  import future.keywords.in

  # ================================================================================
  # HELPER FUNCTIONS
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

  # List of sensitive resource types
  sensitive_resources := [
      "aws_db_instance",
      "aws_rds_cluster",
      "aws_s3_bucket",
      "aws_iam_role",
      "aws_iam_policy",
      "aws_kms_key",
      "aws_security_group",
      "aws_vpc",
      "aws_route53_zone",
  ]

  # ================================================================================
  # ACCESS POLICY - Returns boolean (true = allow, false = deny)
  # ================================================================================

  # Default deny
  default allow = false

  # Allow if no deny rules match
  allow {
      count(deny) == 0
  }

  # CRITICAL: Deny apply if there are any plan policy violations
  deny[msg] {
      input.action == "digger apply"
      count(input.planPolicyViolations) > 0
      msg := sprintf(
          "Cannot apply because plan has %v policy violation(s): %v",
          [count(input.planPolicyViolations), input.planPolicyViolations]
      )
  }

  # Deny apply for production without platform approval
  deny[msg] {
      input.action == "digger apply"
      contains(input.project, "prod")
      not has_team_approval("platform", input.approval_teams)

      msg := sprintf(
          "Production apply requires approval from 'platform' team. Current approval teams: %v",
          [input.approval_teams]
      )
  }

  # Deny apply for production without security approval
  deny[msg] {
      input.action == "digger apply"
      contains(input.project, "prod")
      not has_team_approval("security", input.approval_teams)

      msg := sprintf(
          "Production apply requires approval from 'security' team. Current approval teams: %v",
          [input.approval_teams]
      )
  }

  # Deny apply for non-production without platform approval
  deny[msg] {
      input.action == "digger apply"
      not contains(input.project, "prod")
      not has_team_approval("platform", input.approval_teams)

      msg := sprintf(
          "Apply requires approval from 'platform' team. Current approval teams: %v",
          [input.approval_teams]
      )
  }

  # Deny unlock unless user is in platform team
  deny[msg] {
      input.action == "digger unlock"
      not user_in_team("platform")

      msg := "Unlock requires user to be in 'platform' team"
  }  
