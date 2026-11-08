variable "env" {
  type    = string
  default = "dev"
}

variable "location" {
  type    = string
  default = "centralindia"
}

variable "owner" {
  type    = string
  default = "ai-cloud-security"
}

variable "suffix" {
  description = "Short random suffix so the Key Vault name is globally unique"
  type        = string
}

variable "image" {
  description = "Gateway image, pinned by digest (registry/tripwire@sha256:...)"
  type        = string
  validation {
    condition     = can(regex("@sha256:[a-f0-9]{64}$", var.image))
    error_message = "Pin the image by digest, not by tag."
  }
}

variable "upstream_url" {
  description = "OpenAI-compatible chat completions endpoint (Azure AI Foundry, a Bedrock access gateway, vLLM)"
  type        = string
}
