data "aws_iam_policy_document" "positive3" {
  statement {
    not_actions = ["iam:*"]
    resources   = ["*"]
  }
}
