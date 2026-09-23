resource "aws_iam_policy" "negative1" {
  name = "deny-all-but-mfa-setup"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Deny"
        NotAction = ["iam:CreateVirtualMFADevice", "iam:EnableMFADevice", "sts:GetSessionToken"]
        Resource  = "*"
      },
    ]
  })
}
