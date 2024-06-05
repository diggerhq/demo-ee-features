

resource "aws_ssm_parameter" "foo" {
  name  = "dev/vpc"
  type  = "String"
  value = "10.10.10.0/32"
}
