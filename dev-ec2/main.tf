terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.24.0"
    }
  }
    backend "s3" {
      bucket = "digger-states-test"
      key    = "demo-ee/features/state"
      region = "us-east-1"
    }
}

provider "aws" {
  region = "us-east-1"  # Replace with your desired AWS region
}


resource "aws_ssm_parameter" "foo" {
  name  = "/dev/ec2"
  type  = "String"
  value = "ec2 instance"
}
