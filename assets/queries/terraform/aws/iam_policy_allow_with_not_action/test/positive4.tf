data "aws_iam_policy_document" "positive4" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::reports/*"]
  }

  statement {
    effect      = "Allow"
    not_actions = ["iam:*"]
    resources   = ["*"]
  }
}
