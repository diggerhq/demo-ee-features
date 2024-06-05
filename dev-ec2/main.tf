
resource "aws_ssm_parameter" "foo" {
  name  = "/dev/ec2"
  type  = "String"
  value = "ec2 instance"
}
