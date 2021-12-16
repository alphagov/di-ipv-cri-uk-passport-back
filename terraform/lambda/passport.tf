module "passport" {
  source      = "../modules/endpoint"
  environment = var.environment

  rest_api_id            = aws_api_gateway_rest_api.ipv_cri_uk_passport.id
  rest_api_execution_arn = aws_api_gateway_rest_api.ipv_cri_uk_passport.execution_arn
  root_resource_id       = aws_api_gateway_rest_api.ipv_cri_uk_passport.root_resource_id
  http_method            = "POST"
  path_part              = "passport"
  handler                = "uk.gov.di.ipv.cri.passport.lambda.PassportHandler::handleRequest"
  function_name          = "${var.environment}-passport"
  role_name              = "${var.environment}-passport-role"
}
