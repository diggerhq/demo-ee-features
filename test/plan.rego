
  package digger

  import future.keywords.in

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
  # ================================================================================
  # PLAN POLICY - Returns set of violation messages
  # ================================================================================

  # Plan policy: Deny database changes without platform team approval
  plan[msg] {
      plan_output := input.plan_output
      contains(plan_output, "aws_db_instance")
      not has_team_approval("platform", input.approval_teams)

      msg := sprintf(
          "Database changes require approval from 'platform' team. Approval teams: %v",
          [input.approval_teams]
      )
  }

  # Plan policy: Deny RDS cluster changes without platform team approval
  plan[msg] {
      plan_output := input.plan_output
      contains(plan_output, "aws_rds_cluster")
      not has_team_approval("platform", input.approval_teams)

      msg := sprintf(
          "RDS cluster changes require approval from 'platform' team. Approval teams: %v",
          [input.approval_teams]
      )
  }

  # Plan policy: Deny S3 bucket changes without security team approval
  plan[msg] {
      plan_output := input.plan_output
      contains(plan_output, "aws_s3_bucket")
      not has_team_approval("security", input.approval_teams)

      msg := "S3 bucket changes require approval from 'security' team"
  }

  # Plan policy: Deny IAM role changes without platform approval
  plan[msg] {
      plan_output := input.plan_output
      contains(plan_output, "aws_iam_role")
      not has_team_approval("platform", input.approval_teams)

      msg := sprintf(
          "IAM role changes require approval from 'platform' team. Approval teams: %v",
          [input.approval_teams]
      )
  }

  # Plan policy: Deny IAM role changes without security approval
  plan[msg] {
      plan_output := input.plan_output
      contains(plan_output, "aws_iam_role")
      not has_team_approval("security", input.approval_teams)

      msg := sprintf(
          "IAM role changes require approval from 'security' team. Approval teams: %v",
          [input.approval_teams]
      )
  }

  # Plan policy: Deny IAM policy changes without platform approval
  plan[msg] {
      plan_output := input.plan_output
      contains(plan_output, "aws_iam_policy")
      not has_team_approval("platform", input.approval_teams)

      msg := "IAM policy changes require approval from 'platform' team"
  }

  # Plan policy: Deny IAM policy changes without security approval
  plan[msg] {
      plan_output := input.plan_output
      contains(plan_output, "aws_iam_policy")
      not has_team_approval("security", input.approval_teams)

      msg := "IAM policy changes require approval from 'security' team"
  }

  # Plan policy: Deny KMS key changes without security approval
  plan[msg] {
      plan_output := input.plan_output
      contains(plan_output, "aws_kms_key")
      not has_team_approval("security", input.approval_teams)

      msg := "KMS key changes require approval from 'security' team"
  }

  # Plan policy: Deny security group changes without platform approval
  plan[msg] {
      plan_output := input.plan_output
      contains(plan_output, "aws_security_group")
      not has_team_approval("platform", input.approval_teams)

      msg := "Security group changes require approval from 'platform' team"
  }

  # Plan policy: Deny VPC changes without platform approval
  plan[msg] {
      plan_output := input.plan_output
      contains(plan_output, "aws_vpc")
      not has_team_approval("platform", input.approval_teams)

      msg := "VPC changes require approval from 'platform' team"
  }

  # Plan policy: Deny Route53 changes without platform approval
  plan[msg] {
      plan_output := input.plan_output
      contains(plan_output, "aws_route53_zone")
      not has_team_approval("platform", input.approval_teams)

      msg := "Route53 zone changes require approval from 'platform' team"
  }

