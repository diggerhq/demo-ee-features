
resource "aws_ssm_parameter" "foo" {
  name  = "/prod/ec2"
  type  = "String"
  value = "ec2 prod"
}
