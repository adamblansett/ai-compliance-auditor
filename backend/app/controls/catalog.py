from typing import TypedDict


class BaselineControlSpec(TypedDict):
    control_code: str
    framework: str
    category: str
    title: str
    description: str
    severity: str
    scanner_domains: list[str]
    required_rules: list[str]
    owner_email: str
    remediation_guidance: str


BASELINE_CONTROLS: tuple[BaselineControlSpec, ...] = (
    # SOC 2 Trust Services Criteria (6)
    {
        "control_code": "SOC2-CC6.1",
        "framework": "SOC2",
        "category": "Logical Access Controls",
        "title": "Least-Privilege RBAC & Privileged MFA Enforcement",
        "description": (
            "Logical access to production infrastructure and compliance systems requires scoped "
            "RBAC permissions, MFA on privileged accounts, and separation of duties."
        ),
        "severity": "critical",
        "scanner_domains": ["rbac"],
        "required_rules": ["RBAC-001", "RBAC-002", "RBAC-003"],
        "owner_email": "security@acme-compliance.local",
        "remediation_guidance": (
            "Remove wildcard '*' actions/resources from IAM roles, enforce MFA, and require "
            "dual-control sign-off on high-risk administrative actions."
        ),
    },
    {
        "control_code": "SOC2-CC6.6",
        "framework": "SOC2",
        "category": "System Boundary & Runtime Hardening",
        "title": "Hardened Runtime Config, CORS & Secret Hygiene",
        "description": (
            "External-facing services disable debug mode, avoid wildcard CORS, enforce HTTP "
            "security headers, and inject secrets via a managed vault rather than plaintext files."
        ),
        "severity": "high",
        "scanner_domains": ["config"],
        "required_rules": ["CFG-001", "CFG-002", "CFG-003", "CFG-004"],
        "owner_email": "platform@acme-compliance.local",
        "remediation_guidance": (
            "Set DEBUG=false, replace CORS '*' with explicit trusted origins, rotate any static "
            "secrets into KMS/Vault, and run containers as non-root."
        ),
    },
    {
        "control_code": "SOC2-CC6.7",
        "framework": "SOC2",
        "category": "Transmission & Storage Encryption",
        "title": "Modern TLS Transport & At-Rest Cryptographic Protection",
        "description": (
            "Data in transit uses TLS 1.2/1.3 and data at rest is encrypted with strong AES-256 "
            "or KMS-backed ciphers without legacy weak algorithms."
        ),
        "severity": "critical",
        "scanner_domains": ["encryption"],
        "required_rules": ["ENC-001", "ENC-002", "ENC-003"],
        "owner_email": "security@acme-compliance.local",
        "remediation_guidance": (
            "Disable TLS 1.0/1.1 and weak ciphers (MD5/RC4/ECB), enable AES-256-GCM and KMS "
            "encryption at rest across databases and object stores."
        ),
    },
    {
        "control_code": "SOC2-CC7.2",
        "framework": "SOC2",
        "category": "Security Monitoring & Audit Trail",
        "title": "Structured Audit Logging & Retention Controls",
        "description": (
            "Security-relevant authentication, authorization, and state changes emit structured "
            "correlation-tagged logs retained for at least 90 days."
        ),
        "severity": "high",
        "scanner_domains": ["logging"],
        "required_rules": ["LOG-001", "LOG-003", "LOG-004"],
        "owner_email": "sre@acme-compliance.local",
        "remediation_guidance": (
            "Enable structured JSON logging with X-Request-ID correlation, log auth decisions, "
            "and enforce >=90-day immutable log forwarding."
        ),
    },
    {
        "control_code": "SOC2-CC7.4",
        "framework": "SOC2",
        "category": "Incident Response & Governance",
        "title": "Incident Response & Periodic Access Review SOP",
        "description": (
            "Documented incident escalation playbooks and quarterly access review / offboarding "
            "SOPs are maintained and verifiable."
        ),
        "severity": "medium",
        "scanner_domains": ["sop"],
        "required_rules": ["SOP-001", "SOP-003"],
        "owner_email": "officer@acme-compliance.local",
        "remediation_guidance": (
            "Maintain signed Incident Response and quarterly User Access Review SOPs in version "
            "control."
        ),
    },
    {
        "control_code": "SOC2-C1.2",
        "framework": "SOC2",
        "category": "Confidentiality & Disposal",
        "title": "Confidential Data Retention Ceiling & Disposal Verification",
        "description": (
            "Confidential operational records adhere to documented retention windows with "
            "verified automated disposal or approved legal/business exceptions."
        ),
        "severity": "high",
        "scanner_domains": ["sop", "privacy"],
        "required_rules": ["SOP-004", "PRIV-RET"],
        "owner_email": "privacy@acme-compliance.local",
        "remediation_guidance": (
            "Run scheduled purge jobs to eliminate over-retained datasets or file an approved "
            "time-bounded retention exception."
        ),
    },
    # HIPAA Security & Privacy Safeguards (6)
    {
        "control_code": "HIPAA-164.312(a)(1)",
        "framework": "HIPAA",
        "category": "Technical Safeguards — Access Control",
        "title": "ePHI Access Control, MFA & Session Expiration",
        "description": (
            "Systems storing ePHI enforce unique user identification, MFA, bounded token TTLs, "
            "and zero wildcard admin permissions."
        ),
        "severity": "critical",
        "scanner_domains": ["rbac"],
        "required_rules": ["RBAC-001", "RBAC-002", "RBAC-004"],
        "owner_email": "security@acme-compliance.local",
        "remediation_guidance": (
            "Restrict ePHI roles to explicit clinical/audit scopes, mandate MFA, and cap token "
            "and session lifetimes."
        ),
    },
    {
        "control_code": "HIPAA-164.312(b)",
        "framework": "HIPAA",
        "category": "Technical Safeguards — Audit Controls",
        "title": "ePHI Audit Logging & PHI Log Scrubbing",
        "description": (
            "Hardware and software mechanisms record ePHI access activity while scrubbing raw "
            "MRN, SSN, DOB, and patient identifiers from log streams."
        ),
        "severity": "critical",
        "scanner_domains": ["logging"],
        "required_rules": ["LOG-001", "LOG-002", "LOG-004"],
        "owner_email": "privacy@acme-compliance.local",
        "remediation_guidance": (
            "Enable audit logging on all ePHI endpoints and apply automated PII/PHI redaction "
            "before writing or shipping logs."
        ),
    },
    {
        "control_code": "HIPAA-164.312(e)(1)",
        "framework": "HIPAA",
        "category": "Technical Safeguards — Transmission & Encryption",
        "title": "ePHI Encryption in Transit, at Rest & Key Rotation",
        "description": (
            "ePHI is encrypted with TLS 1.2+/1.3 in transit and AES-256/KMS at rest under an "
            "active key rotation schedule."
        ),
        "severity": "critical",
        "scanner_domains": ["encryption"],
        "required_rules": ["ENC-001", "ENC-002", "ENC-003", "ENC-004"],
        "owner_email": "security@acme-compliance.local",
        "remediation_guidance": (
            "Enforce TLS 1.2+, enable KMS encryption at rest on ePHI datastores, and turn on "
            "automated annual key rotation."
        ),
    },
    {
        "control_code": "HIPAA-164.308(a)(1)",
        "framework": "HIPAA",
        "category": "Administrative Safeguards — Security Management",
        "title": "Hardened ePHI Runtime & Secret Isolation",
        "description": (
            "Production workloads processing regulated health data disable debug flags, "
            "protect credentials, and run with hardened headers."
        ),
        "severity": "high",
        "scanner_domains": ["config"],
        "required_rules": ["CFG-001", "CFG-003", "CFG-004"],
        "owner_email": "platform@acme-compliance.local",
        "remediation_guidance": (
            "Disable debug flags in production manifests and strip any static secrets from env "
            "or container configs."
        ),
    },
    {
        "control_code": "HIPAA-164.308(a)(6)",
        "framework": "HIPAA",
        "category": "Administrative Safeguards — Incident Procedures",
        "title": "Security Incident & PHI Classification Procedures",
        "description": (
            "Documented SOP defines breach triage timelines, PHI classification boundaries, and "
            "escalation channels."
        ),
        "severity": "high",
        "scanner_domains": ["sop"],
        "required_rules": ["SOP-001", "SOP-002"],
        "owner_email": "officer@acme-compliance.local",
        "remediation_guidance": (
            "Publish and review the HIPAA Breach Notification and PHI Data Classification SOP."
        ),
    },
    {
        "control_code": "HIPAA-164.310(d)(2)",
        "framework": "HIPAA",
        "category": "Physical & Disposal Safeguards",
        "title": "ePHI Retention Schedule & Disposal Compliance",
        "description": (
            "Regulated health data respects statutory retention ceilings and documented purge "
            "mechanisms."
        ),
        "severity": "medium",
        "scanner_domains": ["privacy", "sop"],
        "required_rules": ["SOP-004", "PRIV-RET"],
        "owner_email": "privacy@acme-compliance.local",
        "remediation_guidance": (
            "Verify purge automation across ePHI storage tiers and document legal-hold "
            "suspensions."
        ),
    },
    # GDPR Articles (6)
    {
        "control_code": "GDPR-ART15",
        "framework": "GDPR",
        "category": "Data Subject Rights",
        "title": "Right of Access & DSAR 30-Day SLA Governance",
        "description": (
            "Data Subject Access and Portability requests are tracked with 30-day statutory SLA "
            "deadlines and redacted export manifests."
        ),
        "severity": "high",
        "scanner_domains": ["privacy", "sop"],
        "required_rules": ["PRIV-DSAR", "SOP-004"],
        "owner_email": "dpo@acme-compliance.local",
        "remediation_guidance": (
            "Fulfill open DSAR requests before statutory due dates and document subject intake "
            "procedures."
        ),
    },
    {
        "control_code": "GDPR-ART17",
        "framework": "GDPR",
        "category": "Right to Erasure & Storage Limitation",
        "title": "Right to Erasure, Legal-Hold Screening & Retention Limits",
        "description": (
            "Erasure workflows verify active legal holds prior to deletion and systems do not "
            "over-retain personal data past policy limits."
        ),
        "severity": "critical",
        "scanner_domains": ["privacy"],
        "required_rules": ["PRIV-RET", "PRIV-DSAR"],
        "owner_email": "dpo@acme-compliance.local",
        "remediation_guidance": (
            "Resolve overdue DSARs, enforce legal-hold blocks before deletion, and purge expired "
            "personal records."
        ),
    },
    {
        "control_code": "GDPR-ART25",
        "framework": "GDPR",
        "category": "Data Protection by Design & Default",
        "title": "Privacy by Design, Origin Controls & PII Log Scrubbing",
        "description": (
            "Applications minimize personal data exposure via disabled debug output, strict CORS, "
            "and automated PII redaction in logs and cloud prompts."
        ),
        "severity": "high",
        "scanner_domains": ["config", "logging"],
        "required_rules": ["CFG-001", "CFG-002", "LOG-002"],
        "owner_email": "platform@acme-compliance.local",
        "remediation_guidance": (
            "Scrub personal identifiers from application logs and enforce strict origin allowlists."
        ),
    },
    {
        "control_code": "GDPR-ART32",
        "framework": "GDPR",
        "category": "Security of Processing",
        "title": "Encryption, Pseudonymization & Dual-Control Access",
        "description": (
            "Personal data processing incorporates TLS encryption, at-rest encryption, and "
            "separation-of-duties access controls."
        ),
        "severity": "critical",
        "scanner_domains": ["encryption", "rbac"],
        "required_rules": ["ENC-001", "ENC-003", "RBAC-003"],
        "owner_email": "security@acme-compliance.local",
        "remediation_guidance": (
            "Enable TLS 1.2+/1.3, enforce encryption at rest, and apply dual control on personal "
            "data exports."
        ),
    },
    {
        "control_code": "GDPR-ART33",
        "framework": "GDPR",
        "category": "Breach Notification",
        "title": "72-Hour Supervisory Breach Notification Readiness",
        "description": (
            "Incident response SOP includes 72-hour supervisory authority notification workflows "
            "and data classification inventories."
        ),
        "severity": "high",
        "scanner_domains": ["sop"],
        "required_rules": ["SOP-001", "SOP-002"],
        "owner_email": "dpo@acme-compliance.local",
        "remediation_guidance": (
            "Document the 72-hour GDPR Article 33 breach notification runbook and PII taxonomy."
        ),
    },
    {
        "control_code": "GDPR-ART5",
        "framework": "GDPR",
        "category": "Principles Relating to Processing",
        "title": "Purpose Limitation, Classification & Retention Verification",
        "description": (
            "Personal data categories carry verified retention windows and documented "
            "classification standards."
        ),
        "severity": "medium",
        "scanner_domains": ["sop", "privacy"],
        "required_rules": ["SOP-002", "PRIV-RET"],
        "owner_email": "dpo@acme-compliance.local",
        "remediation_guidance": (
            "Maintain up-to-date data classification SOPs and keep all retention stores within "
            "approved durations."
        ),
    },
)
