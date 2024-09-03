terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.24.0"
    }
  }
    backend "s3" {
    bucket = "digger-states-test"              # Change if a different S3 bucket name was used for the backend 
    /* Un-comment to use DynamoDB state locking
    dynamodb_table = "digger-locktable-quickstart-aws"      # Change if a different DynamoDB table name was used for backend
    */
    key    = "terraform/state"
    region = "us-east-1"
  }
}

resource "aws_ssm_parameter" "foo" {
  name  = "/dev/vpc"
  type  = "String"
  value = "10.10.10.0/32"
}

resource "null_resource" "test2" {}
