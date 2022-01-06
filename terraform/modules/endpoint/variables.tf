variable "environment" {
  type = string
}

variable "rest_api_id" {
  type        = string
  description = "id of the API Gateway REST API to register the lambda with"
}

variable "rest_api_execution_arn" {
  type        = string
  description = "ARN of the API Gateway REST API execution role"
}

variable "root_resource_id" {
  type        = string
  description = "id of the root resource within the REST API to register the lambda with"
}

variable "http_method" {
  type        = string
  description = "http request type"
}

variable "path_part" {
  type        = string
  description = "path part to register the new resource under"
}

variable "handler" {
  type        = string
  description = "Class handler for each of the lambdas"
}

variable "function_name" {
  type        = string
  description = "Lambda function name"
}

variable "role_name" {
  type        = string
  description = "Lambda iam role name"
}

variable "env_vars" {
  type        = map
  description = "env vars for the lambda"
  default     = {}
}

variable "allow_access_to_dcs_response_table" {
  type        = bool
  default     = false
  description = "Should the lambda be given access to the dcs-response DynamoDB table"
}

variable "dcs_response_table_policy_arn" {
  type        = string
  default     = null
  description = "ARN of the policy to allow read write to the dcs-response DynamoDB table"
}

variable "allow_access_to_cri_passport_auth_codes_table" {
  type        = bool
  default     = false
  description = "Should the lambda be given access to the cri-passport-auth-codes DynamoDB table"
}

variable "cri_passport_auth_codes_table_policy_arn" {
  type        = string
  default     = null
  description = "ARN of the policy to allow read write to the cri-passport-auth-codes DynamoDB table"
}

variable "allow_access_to_cri_passport_access_tokens_table" {
  type        = bool
  default     = false
  description = "Should the lambda be given access to the cri-passport-access-tokens DynamoDB table"
}

variable "cri_passport_access_tokens_table_policy_arn" {
  type        = string
  default     = null
  description = "ARN of the policy to allow read write to the cri-passport-access-tokens DynamoDB table"
}

locals {
  default_tags = {
    Environment = var.environment
    Source      = "github.com/alphagov/di-ipv-cri-uk-passport-back/terraform/lambda"
  }
}
