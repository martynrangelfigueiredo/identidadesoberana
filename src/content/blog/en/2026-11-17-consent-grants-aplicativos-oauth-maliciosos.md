---
title: "Abusive Consent Grants in Microsoft Security: Threat Hunting and Incident Response Playbook in Microsoft Sentinel"
description: "Comprehensive Microsoft Security playbook for investigating illicit OAuth consent grants, excessive API permissions, consent phishing, and Entra ID containment."
date: 2026-11-17
categoria: IAM
tags: [microsoft-security, sentinel, entra-id, oauth, consent-grant, soc, iam, dfir, kql]
nivel: Avançado
---

The abusive granting of permissions to OAuth applications — commonly referred to as **consent phishing (*illicit consent grants*)** — represents one of the most stealthy and damaging threat vectors in modern cloud environments. Unlike traditional intrusions that rely on stolen credentials or bypassing Multi-Factor Authentication (MFA), this attack tricks legitimate users (or directory administrators) into authorizing a rogue third-party application to access corporate data on their behalf.

Once consent is granted, the application receives Microsoft Graph API access tokens with high-privilege scopes (such as `Mail.ReadWrite`, `Files.ReadWrite.All`, or `User.ReadWrite.All`). From that moment onward, **the adversary requires neither the user's password nor their MFA device**, interacting directly with the organization's cloud resources in an entirely silent manner.

Within the **Microsoft Security** ecosystem, the integration between **Microsoft Entra ID** and **Microsoft Sentinel** equips SOC teams with deep telemetry to uncover anomalous grants, audit API usage, and execute decisive containment against compromised applications.

> 📘 **Official Microsoft Learn References:**
> - [Protecting against illicit consent grant attacks in Microsoft Entra ID (Learn)](https://learn.microsoft.com/entra/identity/enterprise-apps/manage-consent-requests)
> - [Investigating suspicious applications in Microsoft Sentinel (Learn)](https://learn.microsoft.com/azure/sentinel/investigate-incidents)
> - [Microsoft Sentinel built-in analytics rule templates catalog (Learn)](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)

---

## 1. How Does a Consent Phishing Attack Work?

This technique is mapped within **MITRE ATT&CK as T1528 (Steal Application Access Token)** and **T1204.001 (User Execution: Malicious Link)**:

1. **Phishing Lure:** The employee receives a benign-looking internal email (e.g., "Updated Company Policies", "Pending Digital Signature", or "Shared Financial Spreadsheet").
2. **Authentic Microsoft Sign-In Interface:** Clicking the link redirects the user to the genuine Microsoft authentication page (`login.microsoftonline.com`). Because the domain is legitimate, web filters, secure email gateways, and endpoint browsers do not trigger warnings.
3. **Requesting Excessive Scopes:** The application requests delegated permissions to read mail (`Mail.Read`), modify OneDrive/SharePoint files (`Files.ReadWrite.All`), or inspect Teams conversations (`Chat.Read`).
4. **Persistent Access:** The moment the employee clicks "Accept", the adversary obtains a long-lived refresh token, enabling ongoing data exfiltration without generating further user sign-in alerts.

---

## 2. KQL Tip: Mapping OAuth application consent grants in Entra ID

The query below projects helpful fields to contextualize consent events recorded in `AuditLogs`, mapping the target application name, granted permissions, and the authorizing account:

```kql
// ====================================================================================
// Consulta: Mapeando consentimentos de aplicativos OAuth no Entra ID
// Objetivo: Identificar aplicacao alvo, permissoes concedidas, usuario originador e data
// ====================================================================================
let JanelaTempo = 30d;
AuditLogs
| where TimeGenerated >= ago(JanelaTempo)
| where ActivityDisplayName in (
    "Consent to application",
    "Add delegated permission grant",
    "Add app role assignment to service principal"
)
| mv-expand Target = TargetResources
| mv-expand ModProp = Target.modifiedProperties
| where ModProp.displayName in ("ConsentAction.Permissions", "DelegatedPermissionGrant.Scope", "AppRole.Value")
| extend AtorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend NomeAplicativo = tostring(Target.displayName)
| extend IdAplicativo = tostring(Target.id)
| extend Permissoes = tostring(ModProp.newValue)
| project
    TimeGenerated,
    ActivityDisplayName,
    NomeAplicativo,
    IdAplicativo,
    Permissoes,
    AtorUPN,
    Result,
    CorrelationId
| order by TimeGenerated desc
```

### Key analysis checkpoints:
- **`Permissoes`:** Scopes such as `Mail.ReadWrite`, `Mail.Send`, `Files.ReadWrite.All`, and `Directory.AccessAsUser.All` are extremely sensitive when approved for applications from an unverified publisher (*Unverified Publisher*).
- **`AtorUPN`:** Determines whether the grant was approved by an individual employee (*User Consent*) or an administrator approving tenant-wide permissions (*Admin Consent*).
- **`IdAplicativo`:** The unique object identifier of the Service Principal within the tenant, required for immediate containment scripts.

---

## 3. Investigation Playbook: The 5 Mandatory Questions

When triaging alerts in Microsoft Sentinel, analysts must answer:

### 1. What was done?
What application was registered? Is it an external multi-tenant application or an internal tool? Were the permissions delegated (accessing only the user's data) or application-level (tenant-wide access across all mailboxes)?

### 2. Who initiated the consent?
Examine `AtorUPN`. Does the employee have a legitimate business requirement to use this tool? Are they an executive, legal, or finance team member whose mailboxes contain sensitive commercial data?

### 3. Is the publisher verified by Microsoft?
Does the application carry the blue *Verified Publisher* badge? Unverified developers, newly created domains, and look-alike names (e.g., "DocuSign Secure Portal" hosted in an unfamiliar tenant) are critical red flags.

### 4. Is there an approved ticket in the ITSM system?
Query ServiceNow or Jira Service Management. Does a formal IT or security architecture change ticket exist for this integration? If undocumented, treat the alert as a high-confidence threat.

### 5. Has the application initiated API calls?
Inspect `AADServicePrincipalSignInLogs` to verify if the Service Principal has actively acquired tokens and initiated calls against the Microsoft Graph API.

---

## 4. Investigating in the Microsoft Entra Admin Center

For Tier 1 and Tier 2 analysts verifying the application in the portal:

1. Open the **Microsoft Entra admin center** (`entra.microsoft.com`).
2. Navigate to **Identity > Applications > Enterprise applications**.
3. Locate the suspect application in the list and select it.
4. Under **Security**, click **Permissions**:
   - Under **Admin consent**, review tenant-wide permissions.
   - Under **User consent**, identify which employees granted permissions and the explicit scopes involved.
5. Review the application's dedicated **Audit logs** to inspect credential creation, certificate additions, or permission modifications.

---

## 5. Containment and Immediate Incident Response Procedures

Once an application is confirmed malicious or unauthorized, execute containment without delay:

1. **Disable user sign-ins for the application:**
   - Under the Enterprise Application's **Properties**, toggle **Enabled for users to sign-in?** to **No**.
2. **Revoke all granted permissions via PowerShell:**
   ```powershell
   Connect-MgGraph -Scopes "Application.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All"

   $AppObjId = "SERVICE-PRINCIPAL-OBJECT-ID"
   Get-MgServicePrincipalOAuth2PermissionGrant -ServicePrincipalId $AppObjId | ForEach-Object {
       Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $_.Id
   }
   ```
3. **Delete the application from the tenant:**
   - Under **Enterprise applications > Properties**, click **Delete** to remove the Service Principal completely.
4. **Revoke active user sessions:**
   - For all employees who consented to the application, execute `Revoke-MgUserSignOut` and enforce a password change.
5. **Harden tenant consent policies:**
   - Navigate to **Enterprise applications > Consent and permissions > User consent settings**.
   - Set the policy to **Do not allow user consent** and enable the **Admin consent workflow** to ensure security approval for all future apps.

---

## 6. Post-Incident KQL Query: Auditing Service Principal Activity

After removing the application, run the query below to assess whether the Service Principal acquired tokens or accessed tenant resources over the past 14 days:

```kql
// ====================================================================================
// Verificacao Pos-Incidente: Rastreando tokens e logons do Service Principal suspeito
// Objetivo: Verificar se a aplicacao com consentimento abusivo consumiu APIs do tenant
// ====================================================================================
let JanelaAnalise = 14d;
let AppIdSuspeito = "00000000-0000-0000-0000-000000000000";
AADServicePrincipalSignInLogs
| where TimeGenerated >= ago(JanelaAnalise)
| where tolower(AppId) == tolower(AppIdSuspeito)
| extend StatusAutenticacao = iff(ResultType == 0, "Sucesso", "Falha")
| project
    TimeGenerated,
    ServicePrincipalName,
    AppId,
    IPAddress,
    ResourceDisplayName,
    StatusAutenticacao,
    ResultType,
    ResultDescription,
    CorrelationId
| order by TimeGenerated desc
```

### SOC Incident Classification Matrix (TP vs. FP):

| Analysis Scenario | Classification | SOC Action |
|---|---|---|
| Unverified app, unknown publisher, excessive mail permissions (`Mail.ReadWrite`) | **True Positive (Critical)** | Isolate and delete application, revoke user sessions, audit mailbox access logs, and initiate data loss containment. |
| Approved enterprise integration (e.g., official Jira or Power BI plugin) | **False Positive (FP)** | Cross-reference ITSM ticket, confirm publisher verification status, and document exception in Sentinel rule. |
| Tenant-wide Admin Consent granted to suspect external app via compromised admin | **Major Security Incident (P1)** | Escalate immediately to DFIR, isolate application, audit all administrative identities, and conduct full tenant security review. |
