import re
from dataclasses import dataclass

from app.controls.catalog import BASELINE_CONTROLS
from app.llm.pii import redact_pii
from app.scanners.schemas import ScannerPresetOut, TargetType


@dataclass(frozen=True)
class CollectedCheck:
    rule_id: str
    domain: str
    severity: str
    status: str  # "pass" | "fail" | "warning"
    title: str
    detail: str
    remediation: str
    mapped_controls: list[str]
    evidence_snippet: str


def _build_rule_control_map() -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    for spec in BASELINE_CONTROLS:
        for rule_id in spec["required_rules"]:
            mapping.setdefault(rule_id, []).append(spec["control_code"])
    return mapping


RULE_CONTROL_MAP: dict[str, list[str]] = _build_rule_control_map()


def _controls_for(rule_id: str) -> list[str]:
    return list(RULE_CONTROL_MAP.get(rule_id, []))


def _snippet(content: str, pattern: re.Pattern[str] | None = None) -> str:
    if pattern is not None:
        m = pattern.search(content)
        if m:
            start = max(0, m.start() - 40)
            end = min(len(content), m.end() + 80)
            return redact_pii(content[start:end].strip()).redacted_text
    first_lines = " | ".join(line.strip() for line in content.splitlines()[:3] if line.strip())
    return redact_pii(first_lines[:220]).redacted_text


def _collect_config(content: str) -> list[CollectedCheck]:
    checks: list[CollectedCheck] = []

    debug_fail_re = re.compile(
        r"(?im)^[^\n#]*\b(?:debug|app_debug|flask_debug)"
        r"\s*[:=]\s*[\"']?(?:true|1|yes|on)[\"']?\b"
    )
    debug_pass_re = re.compile(
        r"(?im)^[^\n#]*\b(?:debug|app_debug|flask_debug)"
        r"\s*[:=]\s*[\"']?(?:false|0|no|off)[\"']?\b"
    )
    if debug_fail_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="CFG-001",
                domain="config",
                severity="high",
                status="fail",
                title="Debug mode enabled in runtime configuration",
                detail=(
                    "Detected explicit debug=true/1 directive which exposes stack traces "
                    "and internal state."
                ),
                remediation=(
                    "Set DEBUG=false (and APP_DEBUG=false) across all deployed configurations."
                ),
                mapped_controls=_controls_for("CFG-001"),
                evidence_snippet=_snippet(content, debug_fail_re),
            )
        )
    elif debug_pass_re.search(content) or re.search(
        r"(?i)\bapp_env\s*[:=]\s*[\"']?production[\"']?", content
    ):
        checks.append(
            CollectedCheck(
                rule_id="CFG-001",
                domain="config",
                severity="high",
                status="pass",
                title="Debug mode disabled",
                detail="Verified debug flags are disabled or locked for production execution.",
                remediation="Maintain DEBUG=false in production CI/CD validation.",
                mapped_controls=_controls_for("CFG-001"),
                evidence_snippet=_snippet(content, debug_pass_re),
            )
        )
    else:
        checks.append(
            CollectedCheck(
                rule_id="CFG-001",
                domain="config",
                severity="high",
                status="warning",
                title="Debug flag not explicitly declared",
                detail="No explicit DEBUG=false setting found in configuration artifact.",
                remediation="Explicitly declare DEBUG=false in environment configuration.",
                mapped_controls=_controls_for("CFG-001"),
                evidence_snippet=_snippet(content),
            )
        )

    cors_fail_re = re.compile(
        r"(?i)(?:cors_origins?\s*[:=]\s*[\"']?\*[\"']?"
        r"|allow_origins\s*[:=]\s*\[\s*[\"']\*[\"']\s*\]"
        r"|access-control-allow-origin\s*:\s*\*)"
    )
    cors_pass_re = re.compile(
        r"(?i)(?:cors_origins?|allow_origins|access-control-allow-origin)"
    )
    if cors_fail_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="CFG-002",
                domain="config",
                severity="high",
                status="fail",
                title="Wildcard CORS origin ('*') configured",
                detail=(
                    "Wildcard CORS allows arbitrary third-party origins to send "
                    "cross-origin requests."
                ),
                remediation="Replace '*' with an explicit comma-separated origin allowlist.",
                mapped_controls=_controls_for("CFG-002"),
                evidence_snippet=_snippet(content, cors_fail_re),
            )
        )
    elif cors_pass_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="CFG-002",
                domain="config",
                severity="high",
                status="pass",
                title="Explicit CORS origin allowlist enforced",
                detail="CORS configuration declares explicit origins without wildcard '*'.",
                remediation="Periodically audit CORS origin allowlists.",
                mapped_controls=_controls_for("CFG-002"),
                evidence_snippet=_snippet(content, cors_pass_re),
            )
        )
    else:
        checks.append(
            CollectedCheck(
                rule_id="CFG-002",
                domain="config",
                severity="high",
                status="warning",
                title="CORS policy not specified in artifact",
                detail="No CORS origin restriction rule detected in submitted config.",
                remediation="Define explicit CORS_ORIGINS for browser-accessible APIs.",
                mapped_controls=_controls_for("CFG-002"),
                evidence_snippet=_snippet(content),
            )
        )

    secret_fail_re = re.compile(
        r"(?i)(?:dev-insecure-secret|changeme"
        r"|\b(?:password|passwd|api_secret|auth_secret_key|secret_key)\s*[:=]\s*[\"']?"
        r"(?!\$\{|vault:|kms:|env:|secret_manager|\[REDACTED)[A-Za-z0-9_!@#$%^&*-]{4,}"
        r"|AKIA[0-9A-Z]{16}"
        r"|sk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{16,}"
        r"|ghp_[A-Za-z0-9]{20,}"
        r"|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"
    )
    secret_ref_re = re.compile(
        r"(?i)(?:\$\{[A-Z0-9_]+\}|vault:|kms:|secret_manager|aws:secretsmanager)"
    )
    if secret_fail_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="CFG-003",
                domain="config",
                severity="critical",
                status="fail",
                title="Hardcoded credential or insecure default secret detected",
                detail=(
                    "Found plaintext credential, API token, or default dev secret "
                    "in config artifact."
                ),
                remediation=(
                    "Remove static secrets and reference KMS/Vault or injected runtime secrets."
                ),
                mapped_controls=_controls_for("CFG-003"),
                evidence_snippet=_snippet(content, secret_fail_re),
            )
        )
    elif secret_ref_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="CFG-003",
                domain="config",
                severity="critical",
                status="pass",
                title="Secrets externalized to Vault/KMS/env references",
                detail=(
                    "Configuration resolves secrets via secret references without "
                    "hardcoded values."
                ),
                remediation="Rotate managed secrets on regular intervals.",
                mapped_controls=_controls_for("CFG-003"),
                evidence_snippet=_snippet(content, secret_ref_re),
            )
        )
    else:
        checks.append(
            CollectedCheck(
                rule_id="CFG-003",
                domain="config",
                severity="critical",
                status="pass",
                title="No hardcoded secrets or default dev keys detected",
                detail=(
                    "Artifact contains no plaintext API keys, private keys, or "
                    "default dev secrets."
                ),
                remediation="Keep secret scanning active in pre-commit and CI.",
                mapped_controls=_controls_for("CFG-003"),
                evidence_snippet=_snippet(content),
            )
        )

    hardening_fail_re = re.compile(
        r"(?i)(?:privileged\s*:\s*true|\bUSER\s+root\b"
        r"|(?:ssl_verify|verify_ssl|rejectunauthorized)\s*[:=]\s*false)"
    )
    hardening_pass_re = re.compile(
        r"(?i)(?:x-frame-options|x-content-type-options|strict-transport-security"
        r"|user\s+appuser|non-root|read_only\s*:\s*true|ssl_verify\s*[:=]\s*true)"
    )
    if hardening_fail_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="CFG-004",
                domain="config",
                severity="high",
                status="fail",
                title="Insecure runtime privilege or disabled SSL verification",
                detail=(
                    "Detected privileged execution, root user, or disabled TLS "
                    "certificate validation."
                ),
                remediation=(
                    "Run as unprivileged user, enable SSL verification, and inject "
                    "security headers."
                ),
                mapped_controls=_controls_for("CFG-004"),
                evidence_snippet=_snippet(content, hardening_fail_re),
            )
        )
    elif hardening_pass_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="CFG-004",
                domain="config",
                severity="high",
                status="pass",
                title="Runtime security headers and non-root hardening verified",
                detail=(
                    "Verified hardened headers, SSL verification, or unprivileged "
                    "execution directives."
                ),
                remediation="Keep security headers and least-privilege container runtime enforced.",
                mapped_controls=_controls_for("CFG-004"),
                evidence_snippet=_snippet(content, hardening_pass_re),
            )
        )
    else:
        checks.append(
            CollectedCheck(
                rule_id="CFG-004",
                domain="config",
                severity="high",
                status="warning",
                title="Security headers or container privilege directives missing",
                detail="No explicit security-header or non-root directive found in config.",
                remediation="Add X-Frame-Options, HSTS, and unprivileged runtime settings.",
                mapped_controls=_controls_for("CFG-004"),
                evidence_snippet=_snippet(content),
            )
        )

    return checks


def _collect_encryption(content: str) -> list[CollectedCheck]:
    checks: list[CollectedCheck] = []

    tls_fail_re = re.compile(
        r"(?i)(?:\btlsv1(?:\.0|\.1)?(?![.\d])|\btls\s*1\.[01]\b"
        r"|\bsslv[23]\b|http://(?!127\.0\.0\.1|localhost))"
    )
    tls_pass_re = re.compile(
        r"(?i)(?:tlsv1\.[23]|tls\s*1\.[23]|https://|ssl_protocols\s+tlsv1\.[23])"
    )
    if tls_fail_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="ENC-001",
                domain="encryption",
                severity="critical",
                status="fail",
                title="Deprecated TLS 1.0/1.1, SSLv3, or cleartext HTTP detected",
                detail="Transport config allows deprecated TLS/SSL protocols or non-local HTTP.",
                remediation="Restrict ssl_protocols to TLSv1.2 and TLSv1.3 and enforce HTTPS.",
                mapped_controls=_controls_for("ENC-001"),
                evidence_snippet=_snippet(content, tls_fail_re),
            )
        )
    elif tls_pass_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="ENC-001",
                domain="encryption",
                severity="critical",
                status="pass",
                title="Modern TLS 1.2/1.3 transport encryption enforced",
                detail="Transport layer explicitly mandates TLS 1.2 or TLS 1.3.",
                remediation="Continue monitoring cipher suite compatibility.",
                mapped_controls=_controls_for("ENC-001"),
                evidence_snippet=_snippet(content, tls_pass_re),
            )
        )
    else:
        checks.append(
            CollectedCheck(
                rule_id="ENC-001",
                domain="encryption",
                severity="critical",
                status="warning",
                title="TLS protocol version not declared",
                detail="No explicit TLS 1.2/1.3 protocol directive found.",
                remediation="Specify TLSv1.2/TLSv1.3 minimum protocol versions.",
                mapped_controls=_controls_for("ENC-001"),
                evidence_snippet=_snippet(content),
            )
        )

    cipher_fail_re = re.compile(
        r"(?i)\b(?:md5|sha1|rc4|3des|des-cbc|aes-128-ecb|aes-256-ecb|ecb)\b"
    )
    cipher_pass_re = re.compile(
        r"(?i)\b(?:aes-256-gcm|aes256|aes_256|chacha20|sha-?256|sha-?384|ecdhe|argon2|bcrypt)\b"
    )
    if cipher_fail_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="ENC-002",
                domain="encryption",
                severity="high",
                status="fail",
                title="Weak or broken cryptographic cipher/hash referenced",
                detail="Detected legacy algorithm (MD5, SHA1, RC4, 3DES, or ECB mode).",
                remediation="Migrate to AES-256-GCM, ChaCha20-Poly1305, and SHA-256/SHA-384.",
                mapped_controls=_controls_for("ENC-002"),
                evidence_snippet=_snippet(content, cipher_fail_re),
            )
        )
    elif cipher_pass_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="ENC-002",
                domain="encryption",
                severity="high",
                status="pass",
                title="Strong authenticated cryptographic ciphers configured",
                detail="Verified modern AEAD/SHA-256+ ciphers without weak legacy primitives.",
                remediation="Maintain approved cipher suite baseline.",
                mapped_controls=_controls_for("ENC-002"),
                evidence_snippet=_snippet(content, cipher_pass_re),
            )
        )
    else:
        checks.append(
            CollectedCheck(
                rule_id="ENC-002",
                domain="encryption",
                severity="high",
                status="warning",
                title="Cipher suite policy not explicitly listed",
                detail="Artifact does not list cryptographic cipher algorithms.",
                remediation="Explicitly pin AEAD ciphers (AES-256-GCM / ChaCha20).",
                mapped_controls=_controls_for("ENC-002"),
                evidence_snippet=_snippet(content),
            )
        )

    rest_fail_re = re.compile(
        r"(?i)(?:encrypt(?:ion)?_at_rest|sse|storage_encrypted|kms_encrypt(?:ed|ion)?)"
        r"\s*[:=]\s*(?:false|no|off|none|disabled)\b"
    )
    rest_pass_re = re.compile(
        r"(?i)(?:encrypt(?:ion)?_at_rest\s*[:=]\s*true|aws:kms|sse-kms|pgcrypto"
        r"|disk_encryption\s*[:=]\s*true|storage_encrypted\s*[:=]\s*true|aes-256-gcm)"
    )
    if rest_fail_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="ENC-003",
                domain="encryption",
                severity="critical",
                status="fail",
                title="Encryption at rest explicitly disabled",
                detail="Datastore or object storage configuration disables at-rest encryption.",
                remediation=(
                    "Enable SSE-KMS or AES-256 encryption at rest on all volumes and buckets."
                ),
                mapped_controls=_controls_for("ENC-003"),
                evidence_snippet=_snippet(content, rest_fail_re),
            )
        )
    elif rest_pass_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="ENC-003",
                domain="encryption",
                severity="critical",
                status="pass",
                title="Encryption at rest enabled",
                detail="Verified KMS or AES-256 storage encryption is active.",
                remediation="Ensure backups and snapshots inherit KMS encryption.",
                mapped_controls=_controls_for("ENC-003"),
                evidence_snippet=_snippet(content, rest_pass_re),
            )
        )
    else:
        checks.append(
            CollectedCheck(
                rule_id="ENC-003",
                domain="encryption",
                severity="critical",
                status="warning",
                title="At-rest encryption setting omitted",
                detail="No explicit encryption_at_rest / SSE-KMS directive detected.",
                remediation="Explicitly enable KMS-backed encryption at rest.",
                mapped_controls=_controls_for("ENC-003"),
                evidence_snippet=_snippet(content),
            )
        )

    rot_fail_re = re.compile(r"(?i)key_rotation\s*[:=]\s*(?:false|disabled|never|0)\b")
    rot_pass_re = re.compile(
        r"(?i)(?:key_rotation\s*[:=]\s*true|enable_key_rotation|rotation_days"
        r"|strict-transport-security|cert_manager)"
    )
    if rot_fail_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="ENC-004",
                domain="encryption",
                severity="medium",
                status="fail",
                title="Cryptographic key rotation disabled",
                detail="KMS or certificate key rotation is explicitly turned off.",
                remediation="Enable automated key rotation (<= 365 days) and cert-manager renewal.",
                mapped_controls=_controls_for("ENC-004"),
                evidence_snippet=_snippet(content, rot_fail_re),
            )
        )
    elif rot_pass_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="ENC-004",
                domain="encryption",
                severity="medium",
                status="pass",
                title="Key rotation and HSTS/certificate lifecycle active",
                detail="Detected automated key rotation or HSTS lifecycle directives.",
                remediation="Audit rotation timestamps quarterly.",
                mapped_controls=_controls_for("ENC-004"),
                evidence_snippet=_snippet(content, rot_pass_re),
            )
        )
    else:
        checks.append(
            CollectedCheck(
                rule_id="ENC-004",
                domain="encryption",
                severity="medium",
                status="warning",
                title="Key rotation configuration not present",
                detail="No key rotation or certificate lifecycle rule found.",
                remediation="Configure key_rotation=true and HSTS max-age>=31536000.",
                mapped_controls=_controls_for("ENC-004"),
                evidence_snippet=_snippet(content),
            )
        )

    return checks


def _collect_logging(content: str) -> list[CollectedCheck]:
    checks: list[CollectedCheck] = []

    log_fail_re = re.compile(
        r"(?i)(?:audit_log(?:ging)?|logging_enabled)\s*[:=]\s*(?:false|disabled|off)\b"
    )
    log_pass_re = re.compile(
        r"(?i)(?:structlog|x-request-id|correlation_id|trace_id|json_logs"
        r"|audit_log(?:ging)?\s*[:=]\s*(?:true|enabled)|\"event\"\s*:)"
    )
    if log_fail_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="LOG-001",
                domain="logging",
                severity="high",
                status="fail",
                title="Audit logging disabled in service configuration",
                detail="Detected audit_logging=false or logging_enabled=false.",
                remediation="Enable structured JSON audit logging with request correlation IDs.",
                mapped_controls=_controls_for("LOG-001"),
                evidence_snippet=_snippet(content, log_fail_re),
            )
        )
    elif log_pass_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="LOG-001",
                domain="logging",
                severity="high",
                status="pass",
                title="Structured audit logging with correlation IDs active",
                detail="Logs capture structured JSON events or request correlation identifiers.",
                remediation="Ensure every boundary service forwards correlation IDs.",
                mapped_controls=_controls_for("LOG-001"),
                evidence_snippet=_snippet(content, log_pass_re),
            )
        )
    else:
        checks.append(
            CollectedCheck(
                rule_id="LOG-001",
                domain="logging",
                severity="high",
                status="warning",
                title="Structured logging markers not detected",
                detail="Artifact lacks explicit JSON/correlation audit log configuration.",
                remediation="Configure structlog/JSON logging and X-Request-ID propagation.",
                mapped_controls=_controls_for("LOG-001"),
                evidence_snippet=_snippet(content),
            )
        )

    redaction = redact_pii(content)
    redact_off_re = re.compile(
        r"(?i)(?:pii_redaction|log_redaction|scrub_pii|redact)\s*[:=]\s*(?:false|disabled|off)\b"
    )
    if redaction.total_redactions > 0:
        categories = ", ".join(f"{f.category}({f.count})" for f in redaction.findings)
        checks.append(
            CollectedCheck(
                rule_id="LOG-002",
                domain="logging",
                severity="critical",
                status="fail",
                title="Unredacted PII/PHI/credentials exposed in log output",
                detail=f"Detected {redaction.total_redactions} unredacted token(s): {categories}.",
                remediation=(
                    "Pass all log records through PII/PHI scrubbing before stdout or "
                    "SIEM shipping."
                ),
                mapped_controls=_controls_for("LOG-002"),
                evidence_snippet=redaction.redacted_text[:280],
            )
        )
    elif redact_off_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="LOG-002",
                domain="logging",
                severity="critical",
                status="fail",
                title="Log PII/PHI redaction explicitly disabled",
                detail="Found explicit pii_redaction=false or scrub_pii=false directive.",
                remediation=(
                    "Set PII/PHI log redaction to enabled before processing regulated data."
                ),
                mapped_controls=_controls_for("LOG-002"),
                evidence_snippet=_snippet(content, redact_off_re),
            )
        )
    else:
        checks.append(
            CollectedCheck(
                rule_id="LOG-002",
                domain="logging",
                severity="critical",
                status="pass",
                title="Zero unredacted PII, PHI, or credentials in log artifact",
                detail="PII/PHI/secret scanner confirmed zero raw identifiers present.",
                remediation="Keep automated log scrubbing tests in CI.",
                mapped_controls=_controls_for("LOG-002"),
                evidence_snippet=_snippet(content),
            )
        )

    ret_re = re.compile(r"(?i)\b(?:log_)?retention_days\s*[:=]\s*(\d+)\b")
    ret_match = ret_re.search(content)
    immutable_re = re.compile(r"(?i)\b(?:siem|cloudwatch|splunk|loki|immutable_logs)\b")
    if ret_match and int(ret_match.group(1)) < 90:
        days_val = int(ret_match.group(1))
        checks.append(
            CollectedCheck(
                rule_id="LOG-003",
                domain="logging",
                severity="medium",
                status="fail",
                title="Audit log retention below 90-day compliance floor",
                detail=f"Configured log retention of {days_val} days is below the 90-day minimum.",
                remediation=(
                    "Increase audit log retention to >=90 days (365 days recommended for "
                    "HIPAA/SOC 2)."
                ),
                mapped_controls=_controls_for("LOG-003"),
                evidence_snippet=_snippet(content, ret_re),
            )
        )
    elif (ret_match and int(ret_match.group(1)) >= 90) or immutable_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="LOG-003",
                domain="logging",
                severity="medium",
                status="pass",
                title="Centralized >=90-day log retention verified",
                detail="Verified log retention satisfies >=90-day immutable SIEM requirements.",
                remediation="Verify WORM/Object Lock on archive log buckets.",
                mapped_controls=_controls_for("LOG-003"),
                evidence_snippet=_snippet(content, ret_re if ret_match else immutable_re),
            )
        )
    else:
        checks.append(
            CollectedCheck(
                rule_id="LOG-003",
                domain="logging",
                severity="medium",
                status="warning",
                title="Log retention window not explicitly stated",
                detail="No log_retention_days or immutable SIEM sink found in artifact.",
                remediation="Declare retention_days >= 90 and forward logs to immutable storage.",
                mapped_controls=_controls_for("LOG-003"),
                evidence_snippet=_snippet(content),
            )
        )

    auth_fail_re = re.compile(r"(?i)log_auth_events\s*[:=]\s*(?:false|off|no)\b")
    auth_pass_re = re.compile(
        r"(?i)(?:auth_event|login_attempt|rbac_decision|approval\.decided|access_denied"
        r"|log_auth_events\s*[:=]\s*true|actor_role)"
    )
    if auth_fail_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="LOG-004",
                domain="logging",
                severity="high",
                status="fail",
                title="Authentication event logging disabled",
                detail="Auth and authorization event capture is explicitly disabled.",
                remediation="Enable log_auth_events=true across all identity boundaries.",
                mapped_controls=_controls_for("LOG-004"),
                evidence_snippet=_snippet(content, auth_fail_re),
            )
        )
    elif auth_pass_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="LOG-004",
                domain="logging",
                severity="high",
                status="pass",
                title="Authentication and authorization events captured",
                detail="Verified login, RBAC decision, or approval trail events are logged.",
                remediation="Alert on repeated 401/403 authorization failures.",
                mapped_controls=_controls_for("LOG-004"),
                evidence_snippet=_snippet(content, auth_pass_re),
            )
        )
    else:
        checks.append(
            CollectedCheck(
                rule_id="LOG-004",
                domain="logging",
                severity="high",
                status="warning",
                title="Auth event logging coverage unverified",
                detail="Artifact does not show authentication or RBAC audit events.",
                remediation="Instrument auth middleware to log actor_email, role, and outcome.",
                mapped_controls=_controls_for("LOG-004"),
                evidence_snippet=_snippet(content),
            )
        )

    return checks


def _collect_rbac(content: str) -> list[CollectedCheck]:
    checks: list[CollectedCheck] = []

    wild_fail_re = re.compile(
        r"(?i)(?:\"action\"\s*:\s*\"\*\"|\baction\s*[:=]\s*\*|\"resource\"\s*:\s*\"\*\""
        r"|\bresource\s*[:=]\s*\*|\bcluster-admin\b|allow_all\s*[:=]\s*true|\*:\*)"
    )
    scoped_pass_re = re.compile(
        r"(?i)(?:least_privilege|allowed_actions|compliance_officer|auditor|viewer|read_only)"
    )
    if wild_fail_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="RBAC-001",
                domain="rbac",
                severity="critical",
                status="fail",
                title="Wildcard admin permissions ('*' or cluster-admin) detected",
                detail=(
                    "IAM or RBAC policy grants unrestricted wildcard action/resource "
                    "permissions."
                ),
                remediation=(
                    "Replace '*' wildcards with explicitly scoped role actions and resources."
                ),
                mapped_controls=_controls_for("RBAC-001"),
                evidence_snippet=_snippet(content, wild_fail_re),
            )
        )
    elif scoped_pass_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="RBAC-001",
                domain="rbac",
                severity="critical",
                status="pass",
                title="Scoped least-privilege RBAC roles enforced",
                detail="Roles bind explicit action sets without wildcard administrative grants.",
                remediation="Review role permission diffs during quarterly access audits.",
                mapped_controls=_controls_for("RBAC-001"),
                evidence_snippet=_snippet(content, scoped_pass_re),
            )
        )
    else:
        checks.append(
            CollectedCheck(
                rule_id="RBAC-001",
                domain="rbac",
                severity="critical",
                status="warning",
                title="RBAC role scoping rules not explicit",
                detail="Could not verify explicit non-wildcard role permissions.",
                remediation="Define explicit allowlists per role (viewer, auditor, officer).",
                mapped_controls=_controls_for("RBAC-001"),
                evidence_snippet=_snippet(content),
            )
        )

    mfa_fail_re = re.compile(
        r"(?i)(?:mfa_required|require_mfa|enforce_mfa)[\"']?\s*[:=]\s*[\"']?(?:false|no|off)\b"
    )
    mfa_pass_re = re.compile(
        r"(?i)(?:(?:mfa_required|require_mfa|enforce_mfa)[\"']?\s*[:=]\s*[\"']?true"
        r"|aws:MultiFactorAuthPresent|webauthn|totp)"
    )
    if mfa_fail_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="RBAC-002",
                domain="rbac",
                severity="critical",
                status="fail",
                title="MFA disabled for privileged access",
                detail="Policy explicitly sets mfa_required=false or disables MFA enforcement.",
                remediation="Mandate MFA (WebAuthn/TOTP) for all administrative and officer roles.",
                mapped_controls=_controls_for("RBAC-002"),
                evidence_snippet=_snippet(content, mfa_fail_re),
            )
        )
    elif mfa_pass_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="RBAC-002",
                domain="rbac",
                severity="critical",
                status="pass",
                title="MFA enforcement verified",
                detail="Multi-factor authentication condition is required by policy.",
                remediation="Verify hardware/FIDO2 MFA enrollment for admin accounts.",
                mapped_controls=_controls_for("RBAC-002"),
                evidence_snippet=_snippet(content, mfa_pass_re),
            )
        )
    else:
        checks.append(
            CollectedCheck(
                rule_id="RBAC-002",
                domain="rbac",
                severity="critical",
                status="warning",
                title="MFA policy condition missing",
                detail="No explicit MFA enforcement condition found in RBAC policy.",
                remediation="Add mfa_required=true or MultiFactorAuthPresent condition.",
                mapped_controls=_controls_for("RBAC-002"),
                evidence_snippet=_snippet(content),
            )
        )

    sod_fail_re = re.compile(
        r"(?i)(?:(?:separation_of_duties|dual_control)[\"']?\s*[:=]\s*[\"']?(?:false|off)"
        r"|self_approval[\"']?\s*[:=]\s*[\"']?(?:true|allowed))"
    )
    sod_pass_re = re.compile(
        r"(?i)(?:(?:separation_of_duties|enforce_separation_of_duties|dual_control)"
        r"[\"']?\s*[:=]\s*[\"']?true|self_approval[\"']?\s*[:=]\s*[\"']?(?:false|denied))"
    )
    if sod_fail_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="RBAC-003",
                domain="rbac",
                severity="high",
                status="fail",
                title="Separation of duties disabled or self-approval allowed",
                detail="Policy allows requesters to approve their own high-risk actions.",
                remediation="Enable ENFORCE_SEPARATION_OF_DUTIES=true and forbid self-approval.",
                mapped_controls=_controls_for("RBAC-003"),
                evidence_snippet=_snippet(content, sod_fail_re),
            )
        )
    elif sod_pass_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="RBAC-003",
                domain="rbac",
                severity="high",
                status="pass",
                title="Dual-control separation of duties enforced",
                detail="Verified requester and approver roles are isolated by dual-control policy.",
                remediation="Keep HITL approval gates enabled for waivers, releases, and erasures.",
                mapped_controls=_controls_for("RBAC-003"),
                evidence_snippet=_snippet(content, sod_pass_re),
            )
        )
    else:
        checks.append(
            CollectedCheck(
                rule_id="RBAC-003",
                domain="rbac",
                severity="high",
                status="warning",
                title="Separation-of-duties directive absent",
                detail="No explicit dual-control or self_approval restriction declared.",
                remediation="Configure separation_of_duties=true in access policy.",
                mapped_controls=_controls_for("RBAC-003"),
                evidence_snippet=_snippet(content),
            )
        )

    ttl_re = re.compile(r"(?i)\bttl_seconds[\"']?\s*[:=]\s*(\d+)\b")
    sess_re = re.compile(r"(?i)\bsession_timeout_minutes[\"']?\s*[:=]\s*(\d+)\b")
    never_exp_re = re.compile(r"(?i)never_expire[\"']?\s*[:=]\s*[\"']?true\b")
    ttl_m = ttl_re.search(content)
    sess_m = sess_re.search(content)

    if (
        never_exp_re.search(content)
        or (ttl_m and int(ttl_m.group(1)) > 86400)
        or (sess_m and int(sess_m.group(1)) > 480)
    ):
        checks.append(
            CollectedCheck(
                rule_id="RBAC-004",
                domain="rbac",
                severity="high",
                status="fail",
                title="Excessive or non-expiring token/session lifetime",
                detail="Token TTL (>24h), session timeout (>8h), or non-expiring token detected.",
                remediation="Cap token ttl_seconds <= 3600 (max 86400) and session timeout <= 60m.",
                mapped_controls=_controls_for("RBAC-004"),
                evidence_snippet=_snippet(content, ttl_re if ttl_m else sess_re),
            )
        )
    elif ttl_m or sess_m:
        checks.append(
            CollectedCheck(
                rule_id="RBAC-004",
                domain="rbac",
                severity="high",
                status="pass",
                title="Bounded token TTL and session timeout configured",
                detail=(
                    "Access tokens and interactive sessions enforce compliant expiration bounds."
                ),
                remediation="Continue enforcing short-lived JWT TTLs.",
                mapped_controls=_controls_for("RBAC-004"),
                evidence_snippet=_snippet(content, ttl_re if ttl_m else sess_re),
            )
        )
    else:
        checks.append(
            CollectedCheck(
                rule_id="RBAC-004",
                domain="rbac",
                severity="high",
                status="warning",
                title="Session expiration bounds not declared",
                detail="No token TTL or idle session timeout setting found.",
                remediation="Set ttl_seconds <= 3600 and session_timeout_minutes <= 60.",
                mapped_controls=_controls_for("RBAC-004"),
                evidence_snippet=_snippet(content),
            )
        )

    return checks


def _collect_sop(content: str) -> list[CollectedCheck]:
    checks: list[CollectedCheck] = []

    ir_fail_re = re.compile(
        r"(?i)(?:breach_notification_hours\s*[:=]\s*(?:[89]\d|[1-9]\d{2,})|no incident response)"
    )
    ir_pass_re = re.compile(
        r"(?i)(?:incident response|breach notification|72\s*hours|72h|escalation)"
    )
    if ir_fail_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="SOP-001",
                domain="sop",
                severity="high",
                status="fail",
                title="Incident breach notification SLA exceeds 72-hour statutory window",
                detail="SOP specifies notification >72h or omits an incident response plan.",
                remediation=(
                    "Update Incident Response SOP to mandate triage & <=72h regulator "
                    "notification."
                ),
                mapped_controls=_controls_for("SOP-001"),
                evidence_snippet=_snippet(content, ir_fail_re),
            )
        )
    elif ir_pass_re.search(content):
        checks.append(
            CollectedCheck(
                rule_id="SOP-001",
                domain="sop",
                severity="high",
                status="pass",
                title="Incident Response & <=72h breach notification SOP documented",
                detail=(
                    "Verified documented incident response escalation and breach "
                    "notification SLA."
                ),
                remediation="Conduct tabletop incident drill semi-annually.",
                mapped_controls=_controls_for("SOP-001"),
                evidence_snippet=_snippet(content, ir_pass_re),
            )
        )
    else:
        checks.append(
            CollectedCheck(
                rule_id="SOP-001",
                domain="sop",
                severity="high",
                status="warning",
                title="Incident Response procedure not found in SOP",
                detail="Document lacks incident response or 72-hour breach escalation clauses.",
                remediation="Add Incident Response & Breach Notification SLA sections.",
                mapped_controls=_controls_for("SOP-001"),
                evidence_snippet=_snippet(content),
            )
        )

    class_re = re.compile(
        r"(?i)(?:data classification|pii|ephi|\bphi\b|safe harbor|redaction|confidential)"
    )
    checks.append(
        CollectedCheck(
            rule_id="SOP-002",
            domain="sop",
            severity="medium",
            status="pass" if class_re.search(content) else "warning",
            title=(
                "Data classification & PII/PHI handling policy documented"
                if class_re.search(content)
                else "Data classification taxonomy omitted"
            ),
            detail=(
                "Verified PII/PHI data classification tiers and handling requirements."
                if class_re.search(content)
                else "SOP lacks explicit PII/ePHI classification and redaction rules."
            ),
            remediation="Document Confidential/Restricted tiers and mandatory PII/PHI scrubbing.",
            mapped_controls=_controls_for("SOP-002"),
            evidence_snippet=_snippet(content, class_re if class_re.search(content) else None),
        )
    )

    access_rev_re = re.compile(
        r"(?i)(?:access review|quarterly review|offboarding|deprovision|revocation)"
    )
    checks.append(
        CollectedCheck(
            rule_id="SOP-003",
            domain="sop",
            severity="medium",
            status="pass" if access_rev_re.search(content) else "warning",
            title=(
                "Periodic access review & offboarding procedure verified"
                if access_rev_re.search(content)
                else "Access review & offboarding cadence missing"
            ),
            detail=(
                "SOP defines quarterly access recertification and prompt offboarding revocation."
                if access_rev_re.search(content)
                else "No quarterly access review or deprovisioning SLA detected."
            ),
            remediation="Document quarterly RBAC reviews and same-day offboarding revocation.",
            mapped_controls=_controls_for("SOP-003"),
            evidence_snippet=_snippet(
                content, access_rev_re if access_rev_re.search(content) else None
            ),
        )
    )

    ret_sop_re = re.compile(
        r"(?i)(?:dsar|data subject|erasure|legal hold|retention schedule|secure disposal)"
    )
    checks.append(
        CollectedCheck(
            rule_id="SOP-004",
            domain="sop",
            severity="high",
            status="pass" if ret_sop_re.search(content) else "warning",
            title=(
                "DSAR, retention schedule & legal-hold SOP verified"
                if ret_sop_re.search(content)
                else "DSAR & retention disposal workflow missing"
            ),
            detail=(
                "Documented DSAR 30-day fulfillment, legal hold checks, and retention disposal."
                if ret_sop_re.search(content)
                else (
                    "SOP omits DSAR fulfillment, legal hold overrides, or retention "
                    "disposal rules."
                )
            ),
            remediation="Include 30-day DSAR intake, legal-hold checks, and disposal schedules.",
            mapped_controls=_controls_for("SOP-004"),
            evidence_snippet=_snippet(
                content, ret_sop_re if ret_sop_re.search(content) else None
            ),
        )
    )

    return checks


def run_collectors(target_type: TargetType, content: str) -> list[CollectedCheck]:
    """Run one domain collector or the full 5-domain compliance scanner suite."""
    dispatch = {
        "config": _collect_config,
        "encryption": _collect_encryption,
        "logging": _collect_logging,
        "rbac": _collect_rbac,
        "sop": _collect_sop,
    }
    if target_type == "full_suite":
        results: list[CollectedCheck] = []
        for domain in ("config", "encryption", "logging", "rbac", "sop"):
            results.extend(dispatch[domain](content))
        return results
    return dispatch[target_type](content)


SCANNER_PRESETS: tuple[ScannerPresetOut, ...] = (
    ScannerPresetOut(
        preset_id="failing-staging-config",
        label="Failing Staging Env Config",
        target_name="staging-api-env",
        target_type="config",
        artifact_filename="staging.env",
        description=(
            "Insecure staging config with debug mode, wildcard CORS, dev secret, "
            "and disabled SSL verify."
        ),
        content=(
            "APP_ENV=staging\n"
            "DEBUG=true\n"
            "CORS_ORIGINS=*\n"
            "AUTH_SECRET_KEY=dev-insecure-secret-change-in-production-32bytes\n"
            "SSL_VERIFY=false\n"
        ),
    ),
    ScannerPresetOut(
        preset_id="hardened-prod-nginx",
        label="Hardened Prod TLS & Encryption",
        target_name="prod-gateway-tls",
        target_type="encryption",
        artifact_filename="nginx-tls.conf",
        description="Production TLS 1.3 gateway and KMS-encrypted datastore settings.",
        content=(
            "ssl_protocols TLSv1.2 TLSv1.3;\n"
            "ssl_ciphers ECDHE-ECDSA-AES-256-GCM-SHA384:CHACHA20;\n"
            'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";\n'
            "encryption_at_rest=true\n"
            "sse=aws:kms\n"
            "key_rotation=true\n"
        ),
    ),
    ScannerPresetOut(
        preset_id="risky-iam-rbac",
        label="Risky Wildcard IAM RBAC Policy",
        target_name="prod-worker-iam-role",
        target_type="rbac",
        artifact_filename="iam-policy.json",
        description=(
            "Over-privileged IAM policy with wildcard permissions, disabled MFA, "
            "and 7-day tokens."
        ),
        content=(
            "{\n"
            '  "RoleName": "legacy-ops-role",\n'
            '  "Action": "*",\n'
            '  "Resource": "*",\n'
            '  "mfa_required": false,\n'
            '  "separation_of_duties": false,\n'
            '  "ttl_seconds": 604800\n'
            "}\n"
        ),
    ),
    ScannerPresetOut(
        preset_id="phi-logging-leak",
        label="App Log Sample with PHI Leak",
        target_name="ehr-sync-worker-logs",
        target_type="logging",
        artifact_filename="worker.log",
        description="Log stream with unredacted patient SSN/MRN/DOB and short 30-day retention.",
        content=(
            '{"event":"auth_event","actor_role":"auditor","x-request-id":"req-9912"}\n'
            "log_retention_days=30\n"
            "log_auth_events=true\n"
            "INFO patient sync email=pat.jones@clinic.org ssn=123-45-6789 "
            "mrn=MRN-44821 dob=1984-07-19\n"
        ),
    ),
    ScannerPresetOut(
        preset_id="incident-privacy-sop",
        label="Compliant Security & Privacy SOP",
        target_name="corporate-compliance-sop-v3",
        target_type="sop",
        artifact_filename="security-privacy-sop.md",
        description=(
            "Approved SOP covering 72-hour breach response, PII/ePHI classification, "
            "access reviews, and DSARs."
        ),
        content=(
            "# Corporate Security, Incident Response & Privacy SOP\n"
            "1. Incident Response: Security incidents escalate within 1 hour; "
            "supervisory breach notification occurs within 72 hours.\n"
            "2. Data Classification: All PII, ePHI, and payment records require "
            "redaction prior to external transmission.\n"
            "3. Access Review & Offboarding: Quarterly access review and same-day "
            "offboarding revocation apply to all RBAC roles.\n"
            "4. Retention Schedule & DSARs: DSAR requests fulfill within 30 days "
            "after legal hold screening and secure disposal verification.\n"
        ),
    ),
)
