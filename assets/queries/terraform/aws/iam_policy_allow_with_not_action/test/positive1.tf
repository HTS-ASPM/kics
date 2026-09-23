resource "aws_iam_group_policy" "positive1" {
  group = "admins"
  name  = "all-but-ec2"

  policy = <<EOF2
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "NotAction": ["ec2:*"],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF2
}
