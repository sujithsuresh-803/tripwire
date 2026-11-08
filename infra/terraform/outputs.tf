output "gateway_fqdn" {
  value = azurerm_container_app.gw.ingress[0].fqdn
}

output "logs_ingestion_endpoint" {
  value = azurerm_monitor_data_collection_endpoint.dce.logs_ingestion_endpoint
}

output "dcr_immutable_id" {
  value = azurerm_monitor_data_collection_rule.dcr.immutable_id
}

output "gateway_identity_client_id" {
  value = azurerm_user_assigned_identity.gw.client_id
}
