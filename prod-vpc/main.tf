resource "aws_ssm_parameter" "foo" {
  name  = "/prod/vpc"
  type  = "String"
  value = "11.10.10.0/32"
}
