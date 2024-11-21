
resource "aws_instance" "example" {
  ami           = "ami-0e731c8a588258d0d"  # Amazon Linux 2023 AMI in us-east-1
  instance_type = "t2.micro"

  tags = {
    Name = "example-instance"
  }

  vpc_security_group_ids = [aws_security_group.instance.id]
}

resource "aws_security_group" "instance" {
  name = "example-instance"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

output "public_ip" {
  value = aws_instance.example.public_ip
}
