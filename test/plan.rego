
  # List of sensitive resource types that require platform team approval
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

  # Check if plan contains sensitive resource changes
  has_sensitive_changes(plan_output) {
      some resource in sensitive_resources
      contains(plan_output, resource)
  }

  # Check if a specific team is in the approval teams list
  has_team_approval(required_team, approval_teams) {
      some team in approval_teams
      team == required_team
  }

  # Plan policy: Deny if sensitive resources without platform team approval
  plan[msg] {
      plan_output := input.plan_output
      has_sensitive_changes(plan_output)
      not has_team_approval("platform", input.approval_teams)

      msg := sprintf(
          "Plan contains sensitive resource changes but lacks approval from 'platform' team. Approval teams: %v",
          [input.approval_teams]
      )
  }

  # Plan policy: Deny S3 bucket creation without security team approval
  plan[msg] {
      plan_output := input.plan_output
      contains(plan_output, "aws_s3_bucket")
      not has_team_approval("security", input.approval_teams)

      msg := "S3 bucket changes require approval from 'security' team"
  }

  # Plan policy: Deny IAM changes without platform approval
  plan[msg] {
      plan_output := input.plan_output

      # Check for any IAM resource changes
      contains(plan_output, "aws_iam_role")

      not has_team_approval("platform", input.approval_teams)

      msg := sprintf(
          "IAM changes require approval from 'platform' team. Current approval teams: %v",
          [input.approval_teams]
      )
  }

  # Plan policy: Deny IAM changes without security approval
  plan[msg] {
      plan_output := input.plan_output

      # Check for any IAM resource changes
      contains(plan_output, "aws_iam_role")

      not has_team_approval("security", input.approval_teams)

      msg := sprintf(
          "IAM changes require approval from 'security' team. Current approval teams: %v",
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
