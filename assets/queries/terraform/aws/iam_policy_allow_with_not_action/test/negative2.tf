resource "aws_iam_role_policy" "negative2" {
  name = "bucket-all-but-delete"
  role = "app"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        NotAction = ["s3:DeleteObject"]
        Resource  = "arn:aws:s3:::reports/*"
      },
    ]
  })
}
