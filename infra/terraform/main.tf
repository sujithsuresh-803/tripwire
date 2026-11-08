# Tripwire on Azure: gateway on Container Apps, decision logs into a Sentinel workspace through the
# Logs Ingestion API, detections deployed as Sentinel analytics rules from detections/kql.
# Identity is a user-assigned managed identity with two role assignments and nothing else.

terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.0" }
    azapi   = { source = "azure/azapi", version = "~> 2.0" }
  }
}

provider "azurerm" {
  features {}
}

data "azurerm_client_config" "current" {}

locals {
  name = "tripwire-${var.env}"
  tags = { app = "tripwire", env = var.env, owner = var.owner, data_classification = "confidential" }
  kql  = "${path.module}/../../detections/kql"
}

resource "azurerm_resource_group" "rg" {
  name     = "rg-${local.name}"
  location = var.location
  tags     = local.tags
}

# ------------------------------------------------------------------ identity (least privilege)
resource "azurerm_user_assigned_identity" "gw" {
  name                = "id-${local.name}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  tags                = local.tags
}

# ------------------------------------------------------------------ network: gateway and Key Vault stay private
resource "azurerm_virtual_network" "vnet" {
  name                = "vnet-${local.name}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  address_space       = ["10.40.0.0/16"]
  tags                = local.tags
}

resource "azurerm_subnet" "aca" {
  name                 = "snet-aca"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.40.0.0/23"]
  delegation {
    name = "aca"
    service_delegation {
      name    = "Microsoft.App/environments"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet" "pe" {
  name                 = "snet-private-endpoints"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.40.2.0/27"]
}

# Deny inbound from the internet on both subnets; traffic arrives from inside the VNet only
resource "azurerm_network_security_group" "nsg" {
  name                = "nsg-${local.name}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  security_rule {
    name                       = "deny-internet-inbound"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
  tags = local.tags
}

resource "azurerm_subnet_network_security_group_association" "aca" {
  subnet_id                 = azurerm_subnet.aca.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

resource "azurerm_subnet_network_security_group_association" "pe" {
  subnet_id                 = azurerm_subnet.pe.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

resource "azurerm_private_dns_zone" "kv" {
  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = azurerm_resource_group.rg.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "kv" {
  name                  = "kv-link"
  resource_group_name   = azurerm_resource_group.rg.name
  private_dns_zone_name = azurerm_private_dns_zone.kv.name
  virtual_network_id    = azurerm_virtual_network.vnet.id
}

# ------------------------------------------------------------------ secrets
resource "azurerm_key_vault" "kv" {
  name                          = "kv-${replace(local.name, "-", "")}${var.suffix}"
  resource_group_name           = azurerm_resource_group.rg.name
  location                      = azurerm_resource_group.rg.location
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  enable_rbac_authorization     = true
  purge_protection_enabled      = true
  soft_delete_retention_days    = 30
  public_network_access_enabled = false
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
  tags = local.tags
}

resource "azurerm_private_endpoint" "kv" {
  name                = "pe-${local.name}-kv"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  subnet_id           = azurerm_subnet.pe.id
  private_service_connection {
    name                           = "kv"
    private_connection_resource_id = azurerm_key_vault.kv.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "kv"
    private_dns_zone_ids = [azurerm_private_dns_zone.kv.id]
  }
  tags = local.tags
}

resource "azurerm_role_assignment" "kv_reader" {
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets User" # read secrets in this vault only
  principal_id         = azurerm_user_assigned_identity.gw.principal_id
}

# ------------------------------------------------------------------ logging + Sentinel
resource "azurerm_log_analytics_workspace" "law" {
  name                = "log-${local.name}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  sku                 = "PerGB2018"
  retention_in_days   = 90
  tags                = local.tags
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "sentinel" {
  workspace_id = azurerm_log_analytics_workspace.law.id
}

# Custom table for decision logs (azurerm has no resource for custom tables, so azapi)
resource "azapi_resource" "decisions_table" {
  type      = "Microsoft.OperationalInsights/workspaces/tables@2022-10-01"
  name      = "TripwireDecisions_CL"
  parent_id = azurerm_log_analytics_workspace.law.id
  body = {
    properties = {
      retentionInDays = 90
      schema = {
        name = "TripwireDecisions_CL"
        columns = [
          { name = "TimeGenerated", type = "datetime" }, { name = "EventType", type = "string" },
          { name = "RequestId", type = "string" }, { name = "Kind", type = "string" },
          { name = "AgentId", type = "string" }, { name = "Owner", type = "string" },
          { name = "Profile", type = "string" }, { name = "BlastRadius", type = "string" },
          { name = "SessionId", type = "string" }, { name = "Action", type = "string" },
          { name = "Status", type = "int" }, { name = "Severity", type = "string" },
          { name = "Categories", type = "dynamic" }, { name = "Rules", type = "dynamic" },
          { name = "OwaspLlm", type = "dynamic" }, { name = "OwaspAgentic", type = "dynamic" },
          { name = "Atlas", type = "dynamic" }, { name = "DetectOnly", type = "dynamic" },
          { name = "InputHash", type = "string" }, { name = "Input", type = "dynamic" },
          { name = "PolicyVersion", type = "int" }, { name = "Reason", type = "string" },
          { name = "By", type = "string" }, { name = "TimeToContainS", type = "real" },
        ]
      }
    }
  }
}

resource "azurerm_monitor_data_collection_endpoint" "dce" {
  name                          = "dce-${local.name}"
  resource_group_name           = azurerm_resource_group.rg.name
  location                      = azurerm_resource_group.rg.location
  public_network_access_enabled = true # the gateway posts here; access is by Entra token + DCR role only
  tags                          = local.tags
}

resource "azurerm_monitor_data_collection_rule" "dcr" {
  name                        = "dcr-${local.name}"
  resource_group_name         = azurerm_resource_group.rg.name
  location                    = azurerm_resource_group.rg.location
  data_collection_endpoint_id = azurerm_monitor_data_collection_endpoint.dce.id
  destinations {
    log_analytics {
      workspace_resource_id = azurerm_log_analytics_workspace.law.id
      name                  = "law"
    }
  }
  data_flow {
    streams       = ["Custom-TripwireDecisions_CL"]
    destinations  = ["law"]
    output_stream = "Custom-TripwireDecisions_CL"
    transform_kql = "source"
  }
  stream_declaration {
    stream_name = "Custom-TripwireDecisions_CL"
    dynamic "column" {
      for_each = azapi_resource.decisions_table.body.properties.schema.columns
      content {
        name = column.value.name
        type = column.value.type
      }
    }
  }
  tags       = local.tags
  depends_on = [azapi_resource.decisions_table]
}

resource "azurerm_role_assignment" "dcr_publisher" {
  scope                = azurerm_monitor_data_collection_rule.dcr.id
  role_definition_name = "Monitoring Metrics Publisher" # send logs to this DCR only
  principal_id         = azurerm_user_assigned_identity.gw.principal_id
}

# Detections as code: each KQL file becomes a scheduled analytics rule
resource "azurerm_sentinel_alert_rule_scheduled" "rules" {
  for_each = {
    "TW-001" = { file = "TW-001_injection_burst.kql", name = "Tripwire: prompt-injection burst", severity = "High", tactics = ["InitialAccess"] }
    "TW-002" = { file = "TW-002_lethal_trifecta.kql", name = "Tripwire: lethal trifecta egress attempt", severity = "High", tactics = ["Exfiltration"] }
    "TW-003" = { file = "TW-003_campaign.kql", name = "Tripwire: one input across many agents", severity = "Medium", tactics = ["Reconnaissance"] }
    "TW-004" = { file = "TW-004_detect_mode_volume.kql", name = "Tripwire: detect-mode volume (tune policy)", severity = "Low", tactics = ["DefenseEvasion"] }
    "TW-005" = { file = "TW-005_containment.kql", name = "Tripwire: agent containment action", severity = "High", tactics = ["Impact"] }
  }
  name                       = lower(each.key)
  display_name               = each.value.name
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
  severity                   = each.value.severity
  tactics                    = each.value.tactics
  query                      = file("${local.kql}/${each.value.file}")
  query_frequency            = "PT5M"
  query_period               = each.key == "TW-004" ? "P1D" : "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  depends_on                 = [azapi_resource.decisions_table]
}

# ------------------------------------------------------------------ the gateway
resource "azurerm_container_app_environment" "env" {
  name                       = "cae-${local.name}"
  resource_group_name        = azurerm_resource_group.rg.name
  location                   = azurerm_resource_group.rg.location
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.law.id
  infrastructure_subnet_id       = azurerm_subnet.aca.id
  internal_load_balancer_enabled = true # environment has no public IP
  tags                           = local.tags
}

resource "azurerm_container_app" "gw" {
  name                         = "ca-${local.name}"
  resource_group_name          = azurerm_resource_group.rg.name
  container_app_environment_id = azurerm_container_app_environment.env.id
  revision_mode                = "Single"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.gw.id]
  }

  secret {
    name                = "upstream-key"
    key_vault_secret_id = "${azurerm_key_vault.kv.vault_uri}secrets/upstream-key"
    identity            = azurerm_user_assigned_identity.gw.id
  }
  secret {
    name                = "admin-token"
    key_vault_secret_id = "${azurerm_key_vault.kv.vault_uri}secrets/tripwire-admin-token"
    identity            = azurerm_user_assigned_identity.gw.id
  }

  ingress {
    external_enabled = false # reachable only from inside the environment's network
    target_port      = 8080
    transport        = "http"
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas = 2
    max_replicas = 10
    container {
      name   = "tripwire"
      image  = var.image
      cpu    = 0.5
      memory = "1Gi"
      env {
        name  = "TRIPWIRE_UPSTREAM_URL"
        value = var.upstream_url
      }
      env {
        name        = "TRIPWIRE_UPSTREAM_KEY"
        secret_name = "upstream-key"
      }
      env {
        name        = "TRIPWIRE_ADMIN_TOKEN"
        secret_name = "admin-token"
      }
      liveness_probe {
        transport = "HTTP"
        port      = 8080
        path      = "/healthz"
      }
    }
    http_scale_rule {
      name                = "concurrency"
      concurrent_requests = "24" # scale out before the gateway's own 32-request shedding point
    }
  }
  depends_on = [azurerm_role_assignment.kv_reader, azurerm_private_endpoint.kv]
}
