resource "aws_iam_policy" "positive2" {
  name = "all-but-iam"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        NotAction = ["iam:*", "organizations:*"]
        Resource  = "*"
      },
    ]
  })
}
