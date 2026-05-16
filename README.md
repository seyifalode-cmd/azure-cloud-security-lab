# Azure Cloud Security Lab

**Analyst:** Oluwaseyi Michael Falode — Cybersecurity Engineer | Cloud Security Architect
**Platform:** Microsoft Azure (Live Environment — Personal Subscription)
**Date:** May 15, 2026
**Labs Completed:** 7 / 7

---

## Overview

This project demonstrates hands-on implementation of cloud security controls across Microsoft Azure. All 7 labs were performed live in a real Azure environment — not a sandbox or simulator. Each lab covers a critical security domain relevant to enterprise cloud security roles including identity management, secret management, threat detection, security posture management, network security, and automated alerting.

| Domain | Technologies |
|--------|-------------|
| Identity & Access | Microsoft Entra ID · RBAC · IAM |
| Security Monitoring | Microsoft Sentinel (SIEM) · KQL Detection Queries |
| Security Posture | Microsoft Defender for Cloud · CSPM |
| Infrastructure | Azure Virtual Network · Network Security Groups |
| Secrets Management | Azure Key Vault |
| Alerting | Azure Monitor · Action Groups |

---

## Lab Summary

| Lab | Title | Status |
|-----|-------|--------|
| 1 | Microsoft Entra ID — User Provisioning & Role Assignment | ✅ Complete |
| 2 | RBAC & Security Group Management | ✅ Complete |
| 3 | Azure Key Vault — Secret Management & Access Control | ✅ Complete |
| 4 | Microsoft Defender for Cloud — Security Posture Management | ✅ Complete |
| 5 | Microsoft Sentinel — SIEM Configuration & KQL Detection Queries | ✅ Complete |
| 6 | Virtual Network & Network Security Group Rules | ✅ Complete |
| 7 | Azure Monitor — KQL-Based Security Alerting | ✅ Complete |

---

## Lab 1 — Microsoft Entra ID: User Provisioning & Role Assignment

**Objective:** Demonstrate the Joiner process in enterprise IAM — creating a new user identity with least privilege access aligned to their job function.

**What Was Built:**
- Created user John Smith (Security Analyst) with UPN in the Azure tenant
- Assigned **Security Reader** role — read-only access to security information, cannot modify configurations
- Populated identity attributes: Department (Information Security), Job Title, User Type (Member)
- Enforced password change on first login as baseline security control

**Security Principle:** Least Privilege — a Security Analyst needs to read alerts and reports, not manage configurations. Security Reader grants exactly what is needed and nothing more.

---

## Lab 2 — RBAC & Security Group Management

**Objective:** Implement Role-Based Access Control at scale using security groups.

**What Was Built:**
- Created `Security-Team` security group (pure access control, not Microsoft 365)
- Added John Smith as a Direct Member of Security-Team
- Group type: Security with Assigned membership — manual, auditable control

**Security Principle:** RBAC at Scale — when a new analyst joins, add them to Security-Team and they instantly inherit all appropriate access. When they leave, one removal revokes everything.

---

## Lab 3 — Azure Key Vault: Secret Management & Access Control

**Objective:** Deploy Azure Key Vault to centralise secret management — eliminating hardcoded credentials and enforcing separation of duties.

**What Was Built:**
- Deployed `SecurityLabVault-Seyi` Key Vault in Canada Central (data residency compliance)
- Configured Soft Delete (90 days) — mandatory in regulated industries
- Stored `db-connection-password` secret — simulating secure database credential management
- Assigned **Key Vault Secrets Officer** role via RBAC — explicit data plane access separate from resource ownership

**Security Principle:** Separation of Duties — being Owner of a Key Vault does NOT automatically grant access to secrets inside it. Cloud admins manage the vault without seeing passwords. Developers read secrets without managing vault infrastructure.

---

## Lab 4 — Microsoft Defender for Cloud: Security Posture Management

**Objective:** Configure and navigate Microsoft Defender for Cloud — Azure's built-in CSPM tool.

**What Was Explored:**
- Security Posture dashboard — secure score, critical recommendations, attack paths
- Recommendations panel — prioritised list of security improvements by severity
- Security Alerts — active threat detections across the environment
- Regulatory Compliance — framework mapping against PCI-DSS, ISO 27001, NIST, SOC 2
- Workload Protections — per-service coverage across VMs, containers, databases, Key Vault

**Business Relevance:** Regulatory Compliance dashboard provides continuous evidence of compliance posture for auditors — replacing manual spreadsheet assessments with real-time automated control validation.

---

## Lab 5 — Microsoft Sentinel: SIEM Configuration & KQL Detection Queries

**Objective:** Deploy Microsoft Sentinel as a cloud-native SIEM, connect data sources, and write KQL detection queries identifying real-world attack patterns.

**What Was Built:**
- Deployed `SentinelLab-Workspace` Log Analytics Workspace in Canada Central
- Connected **7 Microsoft security data connectors**: Defender XDR, Defender for Identity, Defender for Endpoint, Microsoft 365, Microsoft Entra ID, and more
- Wrote and executed 3 KQL detection queries

**KQL Detection Queries:**

```kql
// Query 1 — Sign-In Activity Monitor
SigninLogs
| where TimeGenerated > ago(24h)
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType
| limit 50
```

```kql
// Query 2 — Brute Force Attack Detection
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != "0"
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress
| where FailedAttempts > 5
| order by FailedAttempts desc
```

```kql
// Query 3 — Unauthorized User Creation Detection
AuditLogs
| where OperationName == "Add user"
| where TimeGenerated > ago(5m)
```

---

## Lab 6 — Virtual Network & Network Security Group Rules

**Objective:** Design and implement network segmentation using Azure VNets and NSGs.

**What Was Built:**
- Created `SecurityLab-VNet` NSG in Canada Central within SecurityLab-RG
- Added custom inbound rule `Allow-HTTPS-Inbound` — Port 443, TCP, Priority 100

**NSG Rules:**

| Priority | Rule | Port | Action | Purpose |
|----------|------|------|--------|---------|
| 100 | Allow-HTTPS-Inbound (custom) | 443 | Allow | HTTPS web traffic from internet |
| 65000 | AllowVnetInBound | Any | Allow | Internal VNet communication |
| 65001 | AllowAzureLoadBalancerInBound | Any | Allow | Load balancer health checks |
| 65500 | DenyAllInBound | Any | Deny | Block all other inbound traffic |

**Security Principle:** Default deny-all architecture — all traffic blocked unless explicitly permitted.

---

## Lab 7 — Azure Monitor: KQL-Based Security Alerting

**Objective:** Build automated security alerting using Azure Monitor and KQL — operationalising detection rules from passive log review to proactive automated threat notification.

**What Was Built:**
- Created alert rule `Detect-New-User-Creation` targeting `SentinelLab-Workspace`
- KQL condition: detects any `Add user` operation in AuditLogs within last 5 minutes
- Alert logic: fires when result count > 0 — zero tolerance for unauthorized user creation
- Evaluation frequency: every 5 minutes — near real-time detection
- Created action group `SecurityAlerts-AG` with Email + SMS notification
- Alert severity: 2 — Warning

**Live Test — Alert Fired Successfully:**
Test user (Jane Doe) created in Entra ID → within 5 minutes KQL query detected the `Add user` audit event → threshold crossed → `SecurityAlerts-AG` triggered → email and SMS notifications sent. Full detection pipeline proven end-to-end.

---

## Key Security Principles Applied

| Principle | Application |
|-----------|------------|
| **Least Privilege** | Every user and service gets only the minimum access required |
| **Defense in Depth** | Multiple security layers: identity, network, data, monitoring |
| **Separation of Duties** | Resource management separated from data access (Key Vault) |
| **Zero Trust** | Never trust, always verify — applied through Conditional Access and RBAC |
| **Proactive Detection** | Automated KQL alerting rather than reactive log review |
| **Data Residency** | All resources deployed in Canada Central for compliance |

---

## Tech Stack

`Microsoft Azure` `Microsoft Entra ID` `Azure RBAC` `Azure Key Vault` `Microsoft Defender for Cloud` `Microsoft Sentinel` `KQL` `Azure Virtual Network` `Network Security Groups` `Azure Monitor` `Log Analytics` `CSPM` `SIEM`

---

## About This Project

This is a live, hands-on Azure cloud security lab completed in a real Azure environment using a personal subscription. It demonstrates practical implementation of enterprise security controls across identity, network, data, and monitoring domains — the core competencies required for Cloud Security Engineer, Security Architect, and SOC roles.
