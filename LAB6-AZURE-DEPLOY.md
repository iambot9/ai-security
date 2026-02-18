# LAB 6: Azure Deployment — Cloud Reference Architecture

**Course:** AI Security & Red Teaming
**Lab:** 6 of 7 — Future Reference
**Prerequisites:** LABs 0–5 complete
**Status:** Reference architecture for future implementation

---

## Purpose

This document is a deployment blueprint, not a hands-on lab. It maps every component built across LABs 0–5 — the vulnerable agent, the attack surface, custom defenses, enterprise tools, agentic security controls, and the AI Gateway — to their Azure equivalents. When you are ready to move from localhost to cloud, this is the reference that tells you what to deploy, why each service was chosen, and how the pieces connect.

The architecture follows zero-trust principles, leverages Azure-native AI security services, and is designed for an enterprise environment where the agent serves multiple consuming teams under centralized governance.

---

## Section 1: Architecture Overview

### Full Deployment Topology

```
                                    ┌──────────────────────────────────────────────────────┐
                                    │                    Azure Subscription                 │
                                    │                                                      │
  Internet                          │  ┌─────────────────────────────────────────────────┐  │
     │                              │  │              Virtual Network (10.0.0.0/16)       │  │
     ▼                              │  │                                                 │  │
┌──────────┐     ┌──────────────┐   │  │  ┌───────────┐    ┌───────────────────────┐     │  │
│  Client   │────▶│ Azure Front  │───┼──┼─▶│  Azure    │───▶│  Azure Container Apps │     │  │
│  Apps     │     │ Door + WAF   │   │  │  │  APIM     │    │  (Agent Runtime)      │     │  │
└──────────┘     └──────────────┘   │  │  │           │    │                       │     │  │
                                    │  │  │  GenAI    │    │  - FastAPI agent      │     │  │
                                    │  │  │  Policies │    │  - Defense middleware  │     │  │
                                    │  │  │  + Auth   │    │  - Tool executors     │     │  │
                                    │  │  └─────┬─────┘    └───────┬───────────────┘     │  │
                                    │  │        │                  │                     │  │
                                    │  │        │           ┌──────┴──────────────┐      │  │
                                    │  │        │           │                     │      │  │
                                    │  │        ▼           ▼                     ▼      │  │
                                    │  │  ┌──────────┐ ┌──────────┐  ┌───────────────┐  │  │
                                    │  │  │ Azure AI │ │ Azure    │  │ Azure SQL /   │  │  │
                                    │  │  │ Content  │ │ OpenAI   │  │ Cosmos DB     │  │  │
                                    │  │  │ Safety   │ │ Service  │  │               │  │  │
                                    │  │  └──────────┘ └──────────┘  └───────────────┘  │  │
                                    │  │        │           │                │           │  │
                                    │  │        └───────────┼────────────────┘           │  │
                                    │  │                    ▼                            │  │
                                    │  │  ┌──────────────────────────────────────┐       │  │
                                    │  │  │  Azure Monitor + Log Analytics       │       │  │
                                    │  │  │  (Diagnostics, KQL, Alerts, Workbooks)│      │  │
                                    │  │  └──────────────────────────────────────┘       │  │
                                    │  │                                                 │  │
                                    │  │  ┌─────────────┐    ┌───────────────────┐       │  │
                                    │  │  │ Azure Key   │    │ Microsoft Entra   │       │  │
                                    │  │  │ Vault       │    │ ID (Auth/RBAC)    │       │  │
                                    │  │  └─────────────┘    └───────────────────┘       │  │
                                    │  └─────────────────────────────────────────────────┘  │
                                    └──────────────────────────────────────────────────────┘
```

### Component Mapping

Every local component built in LABs 0–5 maps to an Azure service. The table below documents each mapping, the recommended SKU for dev/test, and the rationale for service selection.

| Local Component | Azure Service | SKU / Tier | Rationale |
|---|---|---|---|
| FastAPI agent (`main.py`) | Azure Container Apps | Consumption plan | Serverless scaling, no cluster management, built-in ingress. Ideal for HTTP API workloads that don't need GPU. |
| Mock LLM (`mock_llm.py`) | Azure OpenAI Service | Standard (S0), pay-as-you-go | Native OpenAI-compatible API with built-in content filters. Managed model deployments. |
| SQLite database | Azure SQL Database or Cosmos DB | Basic tier (SQL) / Serverless (Cosmos) | Azure SQL for relational data, Cosmos for document/chat history. Basic tier is sufficient for dev/test. |
| Custom defenses (`input_validator.py`, `pii_detector.py`) | Azure AI Content Safety | Standard (S0) | ML-based classifiers replace regex patterns. Continuously updated threat models. Custom categories for org-specific rules. |
| LLM Guard scanners | Azure AI Content Safety + APIM policies | Standard (S0) | Prompt Shields replaces LLM Guard's injection scanner. Platform-managed, no model hosting overhead. |
| Presidio anonymizer | Azure AI Content Safety (PII) + Presidio Service | Standard (S0) | Native PII detection integrated at the platform level. Presidio can also run as a sidecar in ACA if granular control is needed. |
| Guardrails validators | APIM policies + Content Safety | N/A | Output validation moves to gateway-level policy enforcement and Content Safety groundedness detection. |
| Rate limiter (`rate_limiter.py`) | Azure APIM rate-limit policies | Developer tier | `azure-openai-token-limit` enforces token-based rate limiting at the gateway. Platform-enforced, not application-level. |
| RBAC (`rbac.py`) | Microsoft Entra ID app roles | Free tier (included) | OAuth 2.0 + app roles replace static token auth. Integrates with existing enterprise directory. |
| Audit logger (`audit_logger.py`) | Azure Monitor + Log Analytics | Pay-per-GB | Cloud-native structured logging. KQL for querying. Workbooks for dashboards. SIEM integration. |
| AI Gateway (LAB 5) | Azure API Management | Developer tier | GenAI-specific policies (token metrics, semantic cache, content safety integration). Backend pools for load balancing. |
| Secrets in `system_prompt.py` | Azure Key Vault | Standard | Hardware-backed secret storage. Managed identity access. Rotation policies. Audit trail. |
| localhost networking | Azure Virtual Network + Front Door | Standard tier | VNet isolation, private endpoints, WAF, DDoS protection. Zero public endpoints except Front Door. |
| Static API token (`admin123`) | Microsoft Entra ID OAuth 2.0 | Free tier (included) | Enterprise-grade identity. MFA. Conditional Access. Token lifecycle management. |

---

## Section 2: Compute — Azure Container Apps

### Why Azure Container Apps Over AKS

Azure Container Apps (ACA) is the right compute platform for this workload. The agent is an HTTP API backed by FastAPI. It does not require GPU, does not run long-lived background jobs, and does not need custom Kubernetes operators. ACA abstracts away all cluster management while providing the container isolation, scaling, and networking controls needed for a secure deployment.

**ACA advantages for this workload:**

- **Serverless scaling.** Scale to zero during idle periods, scale out on HTTP concurrency. No paying for idle VMs.
- **Simplified networking.** Built-in ingress controller, VNet integration without managing load balancers.
- **Dapr integration.** If the agent needs sidecar patterns (e.g., running Presidio as a sidecar), Dapr is built in.
- **Revision management.** Blue/green deployments with traffic splitting — useful when deploying defense updates.
- **Cost.** Consumption plan charges per vCPU-second and GiB-second. For a dev/test agent handling intermittent traffic, this is materially cheaper than an AKS cluster.

**When to choose AKS instead:**

- Multi-region active-active deployment with custom traffic routing
- GPU workloads (e.g., hosting local LLM models instead of using Azure OpenAI)
- Complex networking requirements (multiple ingress controllers, service mesh)
- Workloads requiring custom Kubernetes operators or CRDs
- Organizations with existing AKS clusters and operational expertise

### Containerization

The agent built across LABs 0–5 already has a Dockerfile from LAB 0. The deployment path:

```
1. Build container image from existing Dockerfile
2. Push to Azure Container Registry (ACR)
3. Deploy to ACA with ACR image reference
4. ACA pulls image from ACR via managed identity
```

**Container image considerations:**

- Base image: `python:3.11-slim` (matches LAB 0 setup)
- Multi-stage build to minimize image size (build dependencies excluded from runtime image)
- Non-root user inside the container
- Health check endpoint exposed at `/health`
- No secrets baked into the image — all injected at runtime

### Environment Configuration

All configuration flows through ACA environment variables, which are backed by Key Vault references:

```
Environment Variable          Source                    LAB Equivalent
─────────────────────────────────────────────────────────────────────
AZURE_OPENAI_ENDPOINT         Key Vault reference       OPENAI_API_KEY (mock)
AZURE_OPENAI_DEPLOYMENT       ACA secret                N/A (new)
DATABASE_CONNECTION_STRING    Key Vault reference       sqlite:///local.db
CONTENT_SAFETY_ENDPOINT       Key Vault reference       N/A (new)
LOG_LEVEL                     ACA environment var       LOG_LEVEL=debug
ALLOWED_ORIGINS               ACA environment var       CORS settings
```

No API keys appear in environment variables. Authentication to Azure OpenAI, SQL, and Content Safety uses managed identity — the identity itself is the credential.

### Scaling Configuration

```yaml
# Conceptual ACA scaling configuration
scale:
  minReplicas: 1          # Always-on for dev/test
  maxReplicas: 10         # Upper bound for cost control
  rules:
    - name: http-scaling
      http:
        metadata:
          concurrentRequests: "20"   # Scale out at 20 concurrent requests
```

For production, consider scaling on custom metrics (e.g., Azure OpenAI token consumption rate) via KEDA scalers.

### Network Isolation

The ACA environment is deployed into a dedicated subnet within the VNet. The agent has **no public endpoint**. Traffic flow:

```
Internet → Front Door → APIM (public, WAF-protected) → ACA (internal only)
```

APIM reaches ACA via the internal VNet. Direct access to ACA from the internet is blocked.

---

## Section 3: AI Model Backend — Azure OpenAI Service

### Deployment Models

Azure OpenAI offers two consumption models. The choice depends on traffic patterns:

| Model | Best For | Billing | Commitment |
|---|---|---|---|
| Pay-as-you-go (Standard) | Dev/test, variable traffic | Per 1K tokens | None |
| Provisioned Throughput Units (PTU) | Production, predictable traffic | Per PTU-hour | 1-month minimum |

For the initial cloud deployment, **pay-as-you-go** is the right choice. PTU becomes relevant when traffic patterns stabilize and cost predictability matters.

### Model Deployments

Deploy two models for cost optimization:

| Deployment Name | Model | Use Case | Input Cost (per 1M tokens) | Output Cost (per 1M tokens) |
|---|---|---|---|---|
| `agent-primary` | GPT-4o | Complex reasoning, tool use, nuanced queries | ~$2.50 | ~$10.00 |
| `agent-routing` | GPT-4o-mini | Classification, routing, simple responses | ~$0.15 | ~$0.60 |

The agent can route requests to the cheaper model for simple tasks (FAQ lookups, classification) and reserve GPT-4o for complex tool-use chains. This mirrors the cost-optimization strategy discussed in LAB 5's gateway tiering.

### Built-in Content Filtering

Azure OpenAI includes default content filters that apply to every API call:

- **Hate and fairness** — Detects content that uses pejorative or discriminatory language
- **Sexual** — Detects sexually explicit content
- **Violence** — Detects content depicting violence or physical harm
- **Self-harm** — Detects content related to self-harm actions
- **Jailbreak risk detection** — Detects prompt injection and jailbreak attempts (preview)

These filters are active by default at `medium` severity. They can be configured (tightened or loosened) per deployment. For the security lab, keep defaults and add Azure AI Content Safety (Section 5) for additional coverage.

**What this means for the lab:** The mock LLM in LAB 1 had no content filtering. Moving to Azure OpenAI adds a baseline content safety layer that the local lab lacked entirely. The LAB 2 attacks that relied on the model producing harmful output will be partially blocked at this level.

### Network Isolation

Azure OpenAI is deployed with a **private endpoint** in the VNet. No public network access is enabled.

```
ACA (agent subnet) → Private Endpoint → Azure OpenAI
```

The private endpoint gets a private IP address in the VNet. DNS resolution within the VNet resolves `your-resource.openai.azure.com` to the private IP, not the public IP.

### Authentication

**Managed identity, not API keys.** The agent's ACA managed identity is granted the `Cognitive Services OpenAI User` role on the Azure OpenAI resource. The Python code changes are minimal:

```python
# LAB 1 (local — mock LLM)
from openai import OpenAI
client = OpenAI(api_key="sk-fake-key", base_url="http://localhost:8000/mock")

# Azure deployment
from openai import AzureOpenAI
from azure.identity import DefaultAzureCredential

credential = DefaultAzureCredential()
token = credential.get_token("https://cognitiveservices.azure.com/.default")

client = AzureOpenAI(
    azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
    azure_ad_token=token.token,
    api_version="2024-10-21"
)
```

No API key in code, no API key in environment variables, no API key in Key Vault. The managed identity **is** the credential.

---

## Section 4: AI Gateway — Azure API Management

### Mapping from LAB 5

LAB 5 built a local AI Gateway with rate limiting, consumer profiles, token tracking, cost allocation, and routing. Azure APIM provides all of this as a managed service with purpose-built GenAI policies.

| LAB 5 Feature | APIM Equivalent | Implementation |
|---|---|---|
| Rate limiting (requests/min) | `rate-limit-by-key` policy | Per-subscription or per-consumer rate limits |
| Token rate limiting | `azure-openai-token-limit` policy | Token-per-minute limits enforced at gateway |
| Cost tracking per consumer | `azure-openai-emit-token-metric` policy | Emits token usage to Application Insights |
| Semantic caching | `azure-openai-semantic-cache-lookup` + `azure-openai-semantic-cache-store` | Redis-backed semantic similarity cache |
| Consumer profiles | APIM Products + Subscriptions | Each team gets a subscription key under a product |
| Model routing | APIM Backend Pools | Load balance or failover across OpenAI deployments |
| Authentication | `validate-azure-ad-token` policy | Entra ID JWT validation at the gateway |
| Logging | APIM Diagnostic Settings | Streams to Log Analytics |

### GenAI-Specific APIM Policies

These policies are purpose-built for Azure OpenAI backends and did not exist in traditional APIM:

**Token Rate Limiting:**
```xml
<azure-openai-token-limit
    tokens-per-minute="10000"
    counter-key="@(context.Subscription.Id)"
    estimate-prompt-tokens="true"
    remaining-tokens-variable-name="remainingTokens" />
```

This replaces the LAB 5 `RateLimitMiddleware`. The gateway estimates prompt tokens before forwarding and enforces limits without waiting for the model response.

**Semantic Caching:**
```xml
<azure-openai-semantic-cache-lookup
    score-threshold="0.8"
    embeddings-backend-id="embeddings-backend"
    embeddings-backend-auth="system-assigned" />
```

Caches responses based on semantic similarity (not exact match). If a new prompt is semantically close to a cached one, the cached response is returned without calling the model. This reduces latency and cost.

**Token Metrics Emission:**
```xml
<azure-openai-emit-token-metric>
    <dimension name="Subscription ID" />
    <dimension name="Product ID" />
    <dimension name="Model" />
</azure-openai-emit-token-metric>
```

Emits prompt tokens, completion tokens, and total tokens as custom metrics — segmented by consumer, product, and model. This is the cloud-native version of LAB 5's cost allocation tracking.

### Backend Pools

APIM can load balance across multiple Azure OpenAI deployments:

```
APIM Backend Pool
├── Azure OpenAI (East US) — priority 1, weight 70
├── Azure OpenAI (West US) — priority 1, weight 30
└── Azure OpenAI (East US 2) — priority 2 (failover)
```

Priority-based routing with weighted distribution. If the primary region hits capacity (HTTP 429), APIM automatically fails over to the secondary. This addresses the single-point-of-failure that the local LAB 5 gateway had.

### Products and Subscriptions

APIM Products map directly to LAB 5's consumer profiles:

| APIM Product | Maps to LAB 5 Profile | Token Limit | Models Allowed |
|---|---|---|---|
| `ai-internal-basic` | Basic consumer | 5,000 TPM | GPT-4o-mini only |
| `ai-internal-standard` | Standard consumer | 20,000 TPM | GPT-4o-mini, GPT-4o |
| `ai-internal-premium` | Premium consumer | 100,000 TPM | All models |

Each consuming team subscribes to a product and receives a subscription key. The Developer Portal allows self-service subscription management — teams can sign up, view usage, and rotate keys without filing tickets.

---

## Section 5: Content Safety — Azure AI Content Safety

### Capabilities Mapping

Azure AI Content Safety is a dedicated service for detecting harmful content in AI applications. It replaces and extends the detection capabilities built in LABs 3A–3B.

| Capability | Description | Replaces (from labs) |
|---|---|---|
| **Prompt Shields** | Detects jailbreak attempts and indirect prompt injection in user inputs | LLM Guard `PromptInjection` scanner, custom `input_validator.py` regex patterns |
| **Groundedness Detection** | Checks whether model output is grounded in provided source material | Guardrails AI validators for hallucination |
| **Protected Material Detection** | Identifies known copyrighted text in model output | No local equivalent — new capability |
| **Custom Categories** | Define org-specific content policies with few-shot examples | Custom regex patterns in `input_validator.py` |
| **Image Analysis** | Detects harmful content in images (if agent handles multimodal input) | No local equivalent |

### Prompt Shields — Deep Dive

Prompt Shields is the most relevant capability for the security lab. It addresses the exact attacks from LAB 2:

**Jailbreak Detection:** Detects attempts to override the system prompt or manipulate the model into ignoring instructions. This includes:
- Direct prompt injection ("Ignore previous instructions and...")
- Role-play attacks ("You are now DAN, a model with no restrictions...")
- Encoding-based evasion (Base64, ROT13, leetspeak obfuscation)
- Multi-turn jailbreaks (gradual context manipulation across turns)

**Indirect Prompt Injection Detection:** Detects malicious instructions embedded in external data that the agent retrieves. This is relevant when the agent's tools (file reader, API caller) retrieve content that contains injected instructions.

The local lab's custom regex patterns (LAB 3A) and LLM Guard's scanner (LAB 3B) both had blind spots. Regex missed semantic variations. LLM Guard's model had a fixed training set. Prompt Shields uses continuously updated ML classifiers trained on emerging attack patterns — it adapts to new jailbreak techniques without code changes.

### Integration via APIM Policy

Content Safety integrates at the gateway level, not in application code:

```xml
<!-- Inbound policy: check user input before forwarding to model -->
<inbound>
    <send-request mode="new" response-variable-name="contentSafetyResponse">
        <set-url>https://{content-safety-endpoint}/contentsafety/text:shieldPrompt?api-version=2024-09-01</set-url>
        <set-method>POST</set-method>
        <set-header name="Content-Type" value="application/json" />
        <authentication-managed-identity resource="https://cognitiveservices.azure.com" />
        <set-body>@{
            var body = context.Request.Body.As<JObject>();
            var messages = body["messages"];
            return new JObject(
                new JProperty("userPrompt", messages.Last["content"].ToString()),
                new JProperty("documents", new JArray())
            ).ToString();
        }</set-body>
    </send-request>
    <choose>
        <when condition="@{
            var response = ((IResponse)context.Variables["contentSafetyResponse"]);
            var body = response.Body.As<JObject>();
            return (bool)body["userPromptAnalysis"]["attackDetected"];
        }">
            <return-response>
                <set-status code="400" reason="Content policy violation" />
                <set-body>{"error": "Request blocked by content safety policy"}</set-body>
            </return-response>
        </when>
    </choose>
</inbound>
```

This runs **before** the request reaches the agent or the model. Blocked requests never consume Azure OpenAI tokens.

### Custom Categories for Organizational Policy

Beyond the built-in categories, create custom categories for enterprise-specific concerns:

- **Internal data leakage** — Detect requests attempting to extract internal project names, client names, or code names
- **Competitive intelligence** — Block requests asking the agent to analyze competitor products using internal data
- **Compliance violations** — Flag requests that could lead to regulatory violations in the agent's domain

Custom categories are defined with a short description and a few positive/negative examples. The service trains a classifier on the fly — no model hosting required.

---

## Section 6: Identity — Microsoft Entra ID

### Eliminating the Static Token

LAB 1 used `admin123` as the authentication token. LAB 3A added RBAC with static roles mapped to static tokens. This was intentionally insecure — the point was to demonstrate the vulnerability. In Azure, authentication and authorization are handled by Microsoft Entra ID (formerly Azure Active Directory).

### App Registrations

Three app registrations are needed:

| App Registration | Purpose | Auth Flow |
|---|---|---|
| `ai-agent-api` | The agent itself (resource/API) | Exposes API permissions, validates tokens |
| `ai-gateway` | APIM (gateway) | Client credentials to call agent and Azure OpenAI |
| `ai-consumer-app` | Consumer applications | Authorization code flow (user-delegated) or client credentials (service-to-service) |

**Token flow:**

```
Consumer App                    APIM Gateway                    Agent (ACA)
     │                              │                              │
     │  1. Get token from           │                              │
     │     Entra ID (OAuth 2.0)     │                              │
     │◄────────────────────────     │                              │
     │                              │                              │
     │  2. Call API with            │                              │
     │     Bearer token             │                              │
     │─────────────────────────────▶│                              │
     │                              │  3. Validate token           │
     │                              │     (validate-azure-ad-token)│
     │                              │                              │
     │                              │  4. Forward (managed identity)│
     │                              │─────────────────────────────▶│
     │                              │                              │
     │                              │  5. Agent validates roles    │
     │                              │     from token claims        │
```

### Managed Identities for Service-to-Service

No credentials stored or transmitted between services. Each service has a system-assigned managed identity:

| Service | Managed Identity Grants | Purpose |
|---|---|---|
| ACA (agent) | `Cognitive Services OpenAI User` on Azure OpenAI | Call the model |
| ACA (agent) | `Key Vault Secrets User` on Key Vault | Read secrets |
| ACA (agent) | `SQL DB Contributor` on Azure SQL | Read/write data |
| APIM | `Cognitive Services User` on Content Safety | Call Prompt Shields |
| APIM | `Cognitive Services OpenAI User` on Azure OpenAI | Semantic cache embeddings |

### Mapping LAB 3A RBAC to Entra ID App Roles

LAB 3A defined three roles: `admin`, `user`, `readonly`. These map to Entra ID app roles defined on the `ai-agent-api` app registration:

```json
{
  "appRoles": [
    {
      "allowedMemberTypes": ["User", "Application"],
      "displayName": "Agent Administrator",
      "description": "Full access including system prompt, config, admin endpoints",
      "value": "Agent.Admin"
    },
    {
      "allowedMemberTypes": ["User", "Application"],
      "displayName": "Agent User",
      "description": "Standard chat and tool access",
      "value": "Agent.User"
    },
    {
      "allowedMemberTypes": ["User", "Application"],
      "displayName": "Agent Reader",
      "description": "Read-only access to conversation history",
      "value": "Agent.Reader"
    }
  ]
}
```

The agent reads the `roles` claim from the validated JWT and enforces authorization. This is the same logical pattern as LAB 3A, but backed by enterprise identity infrastructure instead of a Python dictionary.

### Conditional Access Policies

For admin-level access, enforce additional controls:

- **MFA required** for any token with `Agent.Admin` role
- **Device compliance** required for access from corporate endpoints
- **Location-based** restrictions: block access from outside approved geographies
- **Session controls** for continuous access evaluation

This is where the user's IAM/identity background directly intersects with AI security. Every Conditional Access policy that applies to traditional applications applies identically to AI agent access.

---

## Section 7: Secrets — Azure Key Vault

### The Problem Key Vault Solves

In LAB 1, `system_prompt.py` contained hardcoded secrets:

```python
# LAB 1 — deliberately vulnerable
SYSTEM_PROMPT = """
You are a customer service agent for TechCorp.
Internal admin API key: sk-admin-9f8e7d6c5b4a3
Database password: prod_db_P@ssw0rd!
...
"""
```

The prompt injection attacks in LAB 2 extracted these secrets because they were in-memory strings. Key Vault eliminates this entire vulnerability class.

### Architecture

```
┌──────────────┐         ┌───────────────┐
│  ACA Agent   │────────▶│  Azure Key    │
│  (managed    │  RBAC   │  Vault        │
│   identity)  │◄────────│               │
└──────────────┘         │  Secrets:     │
                         │  - DB conn    │
       No API keys       │  - API keys   │
       No passwords      │  - Config     │
       No secrets in     └───────────────┘
       code or config           │
                                ▼
                         ┌───────────────┐
                         │  Azure Monitor│
                         │  (audit log)  │
                         └───────────────┘
```

### Secret Management

| Secret | Key Vault Secret Name | Rotation Policy | Access Policy |
|---|---|---|---|
| Database connection string | `db-connection-string` | 90 days | ACA managed identity: GET |
| Content Safety endpoint | `content-safety-endpoint` | None (not sensitive) | ACA managed identity: GET |
| External API keys (if any) | `external-api-key-{name}` | 30 days | ACA managed identity: GET |
| Admin configuration | `agent-admin-config` | On change | ACA managed identity: GET |

### Access Policies

Principle of least privilege:

- **ACA managed identity:** GET secrets only. Cannot list, set, or delete.
- **APIM managed identity:** GET secrets only (for any APIM-level secrets).
- **DevOps pipeline identity:** GET + SET (for deployment-time secret seeding).
- **Human administrators:** GET + SET + LIST via Privileged Identity Management (PIM) with just-in-time activation.

No other identities have any access. Key Vault firewall restricts network access to the VNet only.

### Audit Logging

Every secret access is logged:

```
{
  "time": "2026-02-17T10:30:00Z",
  "operationName": "SecretGet",
  "identity": {
    "claim": {
      "oid": "aca-managed-identity-object-id",
      "appid": "aca-managed-identity-client-id"
    }
  },
  "properties": {
    "id": "https://your-vault.vault.azure.net/secrets/db-connection-string",
    "httpStatusCode": 200
  }
}
```

Alert on: unexpected identities accessing secrets, high-frequency access patterns, any LIST or DELETE operations.

### Comparison to LAB 1

| Aspect | LAB 1 (Local) | Azure (Key Vault) |
|---|---|---|
| Where secrets live | Hardcoded in Python source | Hardware-backed vault |
| Who can access | Anyone with file system access | Only managed identities with explicit grants |
| Rotation | Manual code change + redeploy | Automated rotation policies |
| Audit trail | None | Every access logged to Monitor |
| Extraction via prompt injection | Possible (secrets in LLM context) | Not possible (secrets fetched at runtime, not in prompt) |

The critical design change: secrets are **never passed to the LLM**. The system prompt references capabilities, not credentials. Database access uses managed identity — the agent code calls the database without ever handling a password string.

---

## Section 8: Observability — Azure Monitor + Log Analytics

### Replacing File-Based Logging

LAB 3A's `audit_logger.py` wrote structured JSON to a local file. This was sufficient for demonstrating the concept but has fundamental limitations:

- No centralized querying across multiple agent instances
- No real-time alerting
- No correlation with infrastructure metrics
- No retention policies or compliance controls
- No integration with SIEM/SOAR platforms

Azure Monitor with Log Analytics replaces all of this with cloud-native observability.

### Diagnostic Settings

Enable diagnostic logging on every service:

| Service | Diagnostic Categories | Destination |
|---|---|---|
| Azure APIM | GatewayLogs, WebSocketConnectionLogs | Log Analytics workspace |
| Azure Container Apps | ContainerAppConsoleLogs, ContainerAppSystemLogs | Log Analytics workspace |
| Azure OpenAI | RequestResponse, Audit | Log Analytics workspace |
| Azure Key Vault | AuditEvent | Log Analytics workspace |
| Azure AI Content Safety | AuditEvent | Log Analytics workspace |
| Azure Front Door | FrontDoorAccessLog, FrontDoorHealthProbeLog, FrontDoorWebApplicationFirewallLog | Log Analytics workspace |

All logs flow to a single Log Analytics workspace for centralized querying.

### KQL Queries for AI Security Operations

**Top consumers by token usage (past 24 hours):**

```kql
ApiManagementGatewayLogs
| where TimeGenerated > ago(24h)
| where OperationId contains "openai"
| extend SubscriptionId = tostring(parse_json(BackendResponseBody).usage.total_tokens)
| summarize TotalTokens = sum(toint(SubscriptionId)) by SubscriptionName
| order by TotalTokens desc
| take 10
```

**Requests blocked by content filters (past 7 days):**

```kql
ApiManagementGatewayLogs
| where TimeGenerated > ago(7d)
| where ResponseCode == 400
| where ResponseBody contains "content policy"
| summarize BlockedCount = count() by bin(TimeGenerated, 1h), SubscriptionName
| render timechart
```

**Average model latency by deployment (past 1 hour):**

```kql
ApiManagementGatewayLogs
| where TimeGenerated > ago(1h)
| where BackendUrl contains "openai.azure.com"
| extend ModelDeployment = extract("deployments/([^/]+)", 1, BackendUrl)
| summarize
    AvgLatencyMs = avg(TotalTime),
    P95LatencyMs = percentile(TotalTime, 95),
    P99LatencyMs = percentile(TotalTime, 99)
    by ModelDeployment
```

**Estimated cost per team per day:**

```kql
let TokenCostPerMillion = 5.0;  // Blended rate estimate
ApiManagementGatewayLogs
| where TimeGenerated > ago(7d)
| extend TotalTokens = toint(parse_json(BackendResponseBody).usage.total_tokens)
| summarize
    DailyTokens = sum(TotalTokens)
    by bin(TimeGenerated, 1d), SubscriptionName
| extend EstimatedCostUSD = (DailyTokens / 1000000.0) * TokenCostPerMillion
| project TimeGenerated, SubscriptionName, DailyTokens, EstimatedCostUSD
| order by TimeGenerated desc, EstimatedCostUSD desc
```

**Prompt injection detection rate (Content Safety integration):**

```kql
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| where Category == "RequestResponse"
| where OperationName contains "ShieldPrompt"
| extend AttackDetected = parse_json(responseBody_s).userPromptAnalysis.attackDetected
| summarize
    TotalRequests = count(),
    AttacksDetected = countif(AttackDetected == true),
    DetectionRate = round(100.0 * countif(AttackDetected == true) / count(), 2)
    by bin(TimeGenerated, 1h)
| render timechart
```

### Azure Workbooks — CISO Dashboard

Create an Azure Workbook with the following panels:

| Panel | Visualization | Data Source | Purpose |
|---|---|---|---|
| Total Requests (24h) | Single value | APIM logs | Traffic volume indicator |
| Requests Blocked | Single value (red/green) | APIM + Content Safety | Security posture indicator |
| Token Usage by Team | Bar chart | APIM token metrics | Cost allocation visibility |
| Latency Distribution | Histogram | APIM logs | Performance monitoring |
| Content Filter Triggers | Time chart | Content Safety logs | Threat trend analysis |
| Top Blocked Prompts | Table (redacted) | Content Safety logs | Attack pattern intelligence |
| Cost Trend (7d) | Line chart | APIM token metrics | Budget tracking |
| Model Availability | Status indicator | Azure OpenAI health | Uptime monitoring |

This dashboard replaces the terminal output from LAB 3A's audit logger with a visual, shareable, real-time security operations view suitable for executive reporting.

### Alerts

| Alert | Condition | Severity | Action |
|---|---|---|---|
| Budget threshold exceeded | Estimated daily cost > $50 | Warning (Sev 2) | Email + Teams notification |
| Content filter spike | >20 blocked requests in 5 minutes | Critical (Sev 1) | Email + PagerDuty + auto-scale review |
| Unusual traffic pattern | Request volume >3 standard deviations from baseline | Warning (Sev 2) | Email + investigation runbook |
| Model latency degradation | P95 latency >5 seconds for 10 minutes | Warning (Sev 2) | Email + auto-failover to secondary region |
| Key Vault access anomaly | Unexpected identity accessing secrets | Critical (Sev 1) | Email + PagerDuty + block identity |
| Agent crash loop | >3 container restarts in 10 minutes | Critical (Sev 1) | Email + PagerDuty |

---

## Section 9: Network Security

### Virtual Network Design

```
Virtual Network: 10.0.0.0/16
│
├── Subnet: apim-subnet (10.0.1.0/24)
│   └── Azure APIM (internal + external mode)
│
├── Subnet: aca-subnet (10.0.2.0/24)
│   └── Azure Container Apps Environment
│
├── Subnet: private-endpoints (10.0.3.0/24)
│   ├── Azure OpenAI private endpoint
│   ├── Azure Key Vault private endpoint
│   ├── Azure SQL private endpoint
│   ├── Azure AI Content Safety private endpoint
│   └── Azure Container Registry private endpoint
│
└── Subnet: front-door-integration (10.0.4.0/24)
    └── Azure Front Door backend connectivity
```

### Network Security Group Rules

**NSG: apim-subnet-nsg**

| Priority | Direction | Source | Destination | Port | Action | Purpose |
|---|---|---|---|---|---|---|
| 100 | Inbound | AzureFrontDoor.Backend | apim-subnet | 443 | Allow | Front Door to APIM |
| 110 | Inbound | ApiManagement | apim-subnet | 3443 | Allow | APIM management |
| 200 | Outbound | apim-subnet | aca-subnet | 443 | Allow | APIM to agent |
| 210 | Outbound | apim-subnet | private-endpoints | 443 | Allow | APIM to Content Safety |
| 4096 | Inbound | * | * | * | Deny | Default deny |

**NSG: aca-subnet-nsg**

| Priority | Direction | Source | Destination | Port | Action | Purpose |
|---|---|---|---|---|---|---|
| 100 | Inbound | apim-subnet | aca-subnet | 443 | Allow | APIM to agent only |
| 200 | Outbound | aca-subnet | private-endpoints | 443 | Allow | Agent to backend services |
| 4096 | Inbound | * | * | * | Deny | Default deny |

### Traffic Flow (End to End)

```
Client Request
     │
     ▼
Azure Front Door (Global WAF, DDoS L7)
     │  HTTPS only, TLS 1.2+
     │  WAF rules: OWASP Core Rule Set, Bot protection
     │  Header: X-Azure-FDID (validated by APIM)
     │
     ▼
Azure APIM (apim-subnet)
     │  1. Validate Front Door header
     │  2. Validate Entra ID token
     │  3. Check rate limits
     │  4. Call Content Safety (via private endpoint)
     │  5. If safe: forward to agent
     │
     ▼
Azure Container Apps (aca-subnet)
     │  1. Process request
     │  2. Call Azure OpenAI (via private endpoint)
     │  3. Call Azure SQL (via private endpoint)
     │  4. Return response
     │
     ▼
Response flows back through APIM
     │  1. Emit token metrics
     │  2. Cache response (semantic cache)
     │  3. Content Safety on output (optional)
     │  4. Return to client via Front Door
```

### Zero Public Endpoints

Only Azure Front Door has a public endpoint. Every other service is accessible only through the VNet:

| Service | Public Access | Network Access |
|---|---|---|
| Azure Front Door | Yes (public-facing) | Global edge network |
| Azure APIM | No (internal mode) | VNet only, Front Door origin |
| Azure Container Apps | No (internal ingress) | VNet only, APIM origin |
| Azure OpenAI | No (public access disabled) | Private endpoint only |
| Azure Key Vault | No (public access disabled) | Private endpoint only |
| Azure SQL | No (public access disabled) | Private endpoint only |
| Azure AI Content Safety | No (public access disabled) | Private endpoint only |

The local lab ran entirely on `localhost:8000`. This architecture achieves the cloud equivalent of that isolation while allowing controlled external access through the WAF-protected front door.

---

## Section 10: Cost Estimation

### Dev/Test Monthly Estimate

The following estimates assume a single-region dev/test deployment with low traffic (roughly 100 requests/day, average 1,000 tokens per request).

| Service | SKU / Tier | Monthly Estimate | Notes |
|---|---|---|---|
| Azure Container Apps | Consumption | ~$30–50 | 1 replica, ~0.5 vCPU, 1 GiB memory |
| Azure OpenAI Service | Standard (pay-as-you-go) | ~$50–200 | 3M tokens/month at blended rate |
| Azure API Management | Developer tier | ~$50 | Single unit, no SLA (dev/test only) |
| Azure AI Content Safety | Standard (S0) | ~$10–30 | Depends on request volume |
| Azure Key Vault | Standard | ~$1 | Minimal secret operations |
| Log Analytics | Pay-per-GB | ~$10–20 | ~2–5 GB ingestion/month |
| Azure Front Door | Standard | ~$35 | Base fee + per-request charges |
| Azure SQL Database | Basic (5 DTU) | ~$5 | Minimal workload |
| Azure Container Registry | Basic | ~$5 | Image storage |
| Virtual Network + NSGs | Free | $0 | No additional charge |
| Entra ID | Free tier | $0 | Included with subscription |
| **Total (Dev/Test)** | | **~$200–400/month** | |

### Production Cost Considerations

Production deployments introduce materially higher costs:

- **APIM:** Standard or Premium tier ($700–2,800/month per unit) for SLA and VNet integration
- **Azure OpenAI:** Provisioned Throughput Units for predictable performance ($2–6/PTU-hour)
- **ACA:** Multiple replicas across availability zones ($200–500/month)
- **Log Analytics:** Higher ingestion volumes ($2.76/GB after free tier)
- **Front Door:** Premium tier for Private Link origins and enhanced WAF ($330/month base)
- **Estimated production total:** $2,000–8,000/month depending on traffic and model usage

The key cost driver is Azure OpenAI token consumption. Semantic caching (Section 4), model routing between GPT-4o and GPT-4o-mini, and token rate limits are the primary cost optimization levers.

---

## Section 11: Security Posture Comparison

### Local Lab vs. Azure Deployment

| Threat | Local Lab Mitigation | Azure Mitigation | Improvement |
|---|---|---|---|
| Prompt injection | Custom regex + LLM Guard scanner | Azure AI Content Safety Prompt Shields | ML-based, continuously updated by Microsoft security research. No model hosting overhead. Covers indirect injection. |
| Secret exposure | Hardcoded in `system_prompt.py` | Key Vault + managed identity | Secrets never exist in code, config, or environment variables. Hardware-backed storage. Automated rotation. |
| Broken authentication | Static `admin123` token | Entra ID + OAuth 2.0 + MFA + Conditional Access | Enterprise-grade identity with device compliance, location restrictions, continuous access evaluation. |
| Broken authorization | Python dict RBAC in `rbac.py` | Entra ID app roles + APIM product/subscription model | Role assignments in directory, not application code. Centralized governance. |
| Uncontrolled costs | Application-level rate limiter | APIM token-based rate limits + Azure budget alerts | Platform-enforced before requests reach the model. Budget alerts with automated actions. |
| No observability | File-based `audit_logger.py` | Azure Monitor + Log Analytics + Workbooks | Cloud-native SIEM integration, KQL querying, real-time alerting, executive dashboards. |
| Network exposure | `localhost` only (no real exposure) | VNet + private endpoints + WAF + NSGs | Zero trust networking. Private endpoints for all backend services. DDoS protection. Bot detection. |
| Data exfiltration | No controls | Content Safety + private endpoints + NSG egress rules | Model outputs checked for PII/protected material. Network egress restricted to known endpoints. |
| Model abuse | No controls on mock LLM | Azure OpenAI content filters (default) + Content Safety | Multi-layer filtering: built-in Azure OpenAI filters + dedicated Content Safety service. |
| Supply chain | Local pip packages | Azure Container Registry + image scanning | Vulnerability scanning on container images. Admission policies. |
| Audit compliance | Manual log file review | Key Vault audit logs + diagnostic settings + retention policies | Automated compliance reporting. Immutable audit trail. Configurable retention. |

### What the Local Lab Still Teaches

Moving to Azure does not make the local lab obsolete. The local lab teaches:

1. **How attacks work mechanically.** Azure Content Safety blocks prompt injection, but you need to understand *why* it works — the mechanics of LAB 2 attacks remain the foundation.
2. **Defense-in-depth reasoning.** The custom defenses in LAB 3A teach the *thinking* behind security controls. Azure services are implementations of those same principles.
3. **Failure mode analysis.** When Azure Content Safety misses an attack (and it will — no filter is perfect), your LAB 3A/3B knowledge lets you build compensating controls.
4. **Cost vs. security trade-offs.** The local lab runs for free. The Azure deployment costs $200–400/month for dev/test. Understanding what each dollar buys requires understanding what each local component did.

---

## Section 12: Deployment Checklist

The following is the ordered sequence of steps for when this reference architecture is expanded into a full implementation lab. Each step will become a section with Bicep/Terraform templates, CLI commands, and verification tests.

### Phase 1: Foundation (Networking + Secrets)

- [ ] 1. **Create resource group** — Single resource group for all lab resources. Tag with `project:ai-security-lab`, `environment:dev`.
- [ ] 2. **Deploy Virtual Network** — Address space `10.0.0.0/16` with four subnets (apim, aca, private-endpoints, front-door). Apply NSG rules from Section 9.
- [ ] 3. **Deploy Azure Key Vault** — Standard tier. Enable soft delete and purge protection. Disable public network access. Create private endpoint in `private-endpoints` subnet.
- [ ] 4. **Seed initial secrets** — Database connection string, Content Safety endpoint, any external API keys. Use deployment pipeline identity.

### Phase 2: AI Backend (Model + Safety)

- [ ] 5. **Deploy Azure OpenAI Service** — Create resource. Disable public network access. Create private endpoint. Deploy `gpt-4o` and `gpt-4o-mini` models.
- [ ] 6. **Configure content filters** — Review default filter settings on each deployment. Tighten if needed for the lab's domain.
- [ ] 7. **Deploy Azure AI Content Safety** — Standard tier. Disable public network access. Create private endpoint. Configure custom categories for org-specific policies.
- [ ] 8. **Deploy Azure SQL Database** — Basic tier. Disable public network access. Create private endpoint. Run schema migration from LAB 1's SQLite schema.

### Phase 3: Gateway (APIM + Front Door)

- [ ] 9. **Deploy Azure APIM** — Developer tier for dev/test. Deploy into `apim-subnet` with internal + external mode. Configure system-assigned managed identity.
- [ ] 10. **Configure APIM GenAI policies** — Token rate limiting, semantic caching, token metric emission, Entra ID token validation. Reference Section 4 policy examples.
- [ ] 11. **Create APIM products and subscriptions** — Three products mapping to LAB 5 consumer profiles. Create test subscriptions.
- [ ] 12. **Configure APIM backend pools** — Point to Azure OpenAI private endpoint. Configure health probes and failover.
- [ ] 13. **Deploy Azure Front Door** — Standard tier with WAF. Configure origin group pointing to APIM. Enable OWASP Core Rule Set and bot protection.

### Phase 4: Application (Agent + Identity)

- [ ] 14. **Deploy Azure Container Registry** — Basic tier. Build and push agent container image.
- [ ] 15. **Deploy Azure Container Apps** — Consumption plan in `aca-subnet`. Configure managed identity with Key Vault, Azure OpenAI, SQL, and Content Safety access. Internal ingress only.
- [ ] 16. **Configure Entra ID app registrations** — Three registrations per Section 6. Define app roles. Configure managed identity role assignments.
- [ ] 17. **Update agent code** — Swap mock LLM client for `AzureOpenAI` client. Replace hardcoded config with Key Vault references. Replace static auth with Entra ID token validation.

### Phase 5: Observability + Validation

- [ ] 18. **Configure diagnostic settings** — Enable on all services per Section 8 table. Point to single Log Analytics workspace.
- [ ] 19. **Deploy Azure Workbook** — CISO dashboard with panels from Section 8.
- [ ] 20. **Configure alerts** — Budget threshold, content filter spike, latency degradation, crash loop, Key Vault anomaly.
- [ ] 21. **Run LAB 2 attacks against cloud deployment** — Execute the same attack scripts from LAB 2 against the Azure-deployed agent. Document which attacks are blocked at which layer.
- [ ] 22. **Compare security posture** — Fill in the Section 11 comparison table with actual results. Identify any gaps where local defenses caught attacks that Azure services missed.
- [ ] 23. **Cost validation** — After one week of dev/test usage, compare actual costs against Section 10 estimates. Adjust scaling and tier selections.

---

## Infrastructure as Code

When this lab is implemented, all resources should be deployed using Bicep or Terraform — not portal clicks. The deployment checklist above maps to IaC modules:

```
infra/
├── main.bicep                    # Orchestrator
├── modules/
│   ├── networking.bicep          # VNet, subnets, NSGs, private DNS zones
│   ├── keyvault.bicep            # Key Vault + private endpoint + access policies
│   ├── openai.bicep              # Azure OpenAI + model deployments + private endpoint
│   ├── content-safety.bicep      # AI Content Safety + private endpoint
│   ├── sql.bicep                 # Azure SQL + private endpoint
│   ├── apim.bicep                # APIM + policies + products + backends
│   ├── frontdoor.bicep           # Front Door + WAF + origins
│   ├── container-apps.bicep      # ACA environment + app + scaling rules
│   ├── monitoring.bicep          # Log Analytics + diagnostic settings + alerts
│   └── identity.bicep            # Entra ID app registrations + role assignments
├── parameters/
│   ├── dev.bicepparam            # Dev/test parameter values
│   └── prod.bicepparam           # Production parameter values
└── scripts/
    ├── deploy.sh                 # Full deployment script
    └── seed-secrets.sh           # Key Vault secret seeding
```

Each module should be independently deployable for iterative development during the future lab session.

---

## Appendix: Azure CLI Quick Reference

Commands for validating the deployment. These are not step-by-step instructions — they are reference commands for the future implementation session.

```bash
# Resource group
az group create --name rg-ai-security-lab --location eastus

# Key Vault
az keyvault create --name kv-ai-sec-lab --resource-group rg-ai-security-lab \
  --enable-soft-delete true --enable-purge-protection true \
  --public-network-access Disabled

# Azure OpenAI
az cognitiveservices account create --name oai-ai-sec-lab \
  --resource-group rg-ai-security-lab --kind OpenAI --sku S0 \
  --location eastus --custom-domain oai-ai-sec-lab

# Model deployment
az cognitiveservices account deployment create \
  --name oai-ai-sec-lab --resource-group rg-ai-security-lab \
  --deployment-name agent-primary --model-name gpt-4o \
  --model-version "2024-11-20" --model-format OpenAI \
  --sku-capacity 10 --sku-name Standard

# Content Safety
az cognitiveservices account create --name cs-ai-sec-lab \
  --resource-group rg-ai-security-lab --kind ContentSafety \
  --sku S0 --location eastus

# Container Apps
az containerapp env create --name cae-ai-sec-lab \
  --resource-group rg-ai-security-lab --location eastus \
  --infrastructure-subnet-resource-id "/subscriptions/.../subnets/aca-subnet" \
  --internal-only true

# APIM
az apim create --name apim-ai-sec-lab --resource-group rg-ai-security-lab \
  --publisher-email admin@contoso.com --publisher-name "AI Security Lab" \
  --sku-name Developer --virtual-network Internal

# Verify private endpoints
az network private-endpoint list --resource-group rg-ai-security-lab \
  --output table

# Verify managed identity role assignments
az role assignment list --assignee <aca-managed-identity-id> --output table
```

---

## Next Steps

This document serves as the architectural foundation for LAB 6 implementation. When ready to proceed:

1. Review this architecture against current Azure service availability and pricing (services and pricing change frequently).
2. Decide on Bicep vs. Terraform based on team preference and existing IaC tooling.
3. Estimate actual token consumption from LAB 2 attack runs to refine the cost model.
4. Expand each checklist item into a step-by-step section with commands, expected outputs, and verification steps.
5. Build a companion LAB 7 that runs the full LAB 2 attack suite against the Azure deployment and produces a comparative security assessment.

The gap between running security labs on localhost and deploying secure AI systems in production is where architectural decisions compound. This reference ensures those decisions are made deliberately, not discovered retroactively.
