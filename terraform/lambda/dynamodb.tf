resource "aws_dynamodb_table" "cri-passport-credentials" {
  name         = "${var.environment}-cri-passport-credentials"
  hash_key     = "ipvSessionId"
  range_key    = "requestId"
  billing_mode = "PAY_PER_REQUEST"

  attribute {
    name = "ipvSessionId"
    type = "S"
  }

  attribute {
    name = "requestId"
    type = "S"
  }

  tags = local.default_tags
}

resource "aws_dynamodb_table" "cri-passport-auth-codes" {
  name         = "${var.environment}-cri-passport-auth-codes"
  hash_key     = "authCode"
  billing_mode = "PAY_PER_REQUEST"

  attribute {
    name = "authCode"
    type = "S"
  }

  tags = local.default_tags
}

resource "aws_dynamodb_table" "cri-passport-access-tokens" {
  name         = "${var.environment}-cri-passport-access-tokens"
  hash_key     = "accessToken"
  billing_mode = "PAY_PER_REQUEST"

  attribute {
    name = "accessToken"
    type = "S"
  }

  tags = local.default_tags
}

resource "aws_iam_policy" "policy-cri-passport-credentials-table" {
  name = "policy-cri-passport-credentials-table"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "PolicyCriPassportCredentialsTable"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:BatchWriteItem",
          "dynamodb:GetItem",
          "dynamodb:BatchGetItem",
          "dynamodb:Scan",
          "dynamodb:Query",
          "dynamodb:ConditionCheckItem"
        ]
        Effect = "Allow"
        Resource = [
          aws_dynamodb_table.cri-passport-credentials.arn,
          "${aws_dynamodb_table.cri-passport-credentials.arn}/index/*"
        ]
      },
    ]
  })
}

resource "aws_iam_policy" "policy-cri-passport-auth-codes-table" {
  name = "policy-cri-passport-auth-codes-table"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "PolicyCriPassportAuthCodesTable"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query"
        ]
        Effect = "Allow"
        Resource = [
          aws_dynamodb_table.cri-passport-auth-codes.arn,
          "${aws_dynamodb_table.cri-passport-auth-codes.arn}/index/*"
        ]
      },
    ]
  })
}

resource "aws_iam_policy" "policy-cri-passport-access-tokens-table" {
  name = "policy-cri-passport-access-tokens-table"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "PolicyCriPassportAccessTokensTable"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query"
        ]
        Effect = "Allow"
        Resource = [
          aws_dynamodb_table.cri-passport-access-tokens.arn,
          "${aws_dynamodb_table.cri-passport-access-tokens.arn}/index/*"
        ]
      },
    ]
  })
}