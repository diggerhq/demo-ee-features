
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

  # ================================================================================
  # PLAN POLICY - Also uses deny (not plan)
  # ================================================================================

  # Deny if null_resource changes without platform team approval (for testing)
  deny[msg] {
      resource := input.terraform.resource_changes[_]
      resource.type == "null_resource"
      not has_team_approval("platform", input.approval_teams)

      msg := sprintf(
          "null_resource changes require approval from 'platform' team. Current approval teams: %v",
          [input.approval_teams]
      )
  }

  # Deny if IAM changes without platform team approval
  deny[msg] {
      resource := input.terraform.resource_changes[_]
      resource.type == "aws_iam"

      not has_team_approval("platform", input.approval_teams)

      msg := sprintf(
          "IAM changes require approval from 'platform' team. Current approval teams: %v",
          [input.approval_teams]
      )
  }

  # Deny if IAM changes without security team approval
  deny[msg] {
      resource := input.terraform.resource_changes[_]
      resource.type == "aws_iam"
      not has_team_approval("security", input.approval_teams)

      msg := sprintf(
          "IAM changes require approval from 'security' team. Current approval teams: %v",
          [input.approval_teams]
      )
  }
