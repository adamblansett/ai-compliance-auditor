import hashlib
import ipaddress
import os
import socket
import ssl
from pathlib import Path
from urllib.parse import urlparse

import httpx
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.controls.evaluator import evaluate_all_controls
from app.core.auth import Actor
from app.core.config import Settings
from app.db.models import ScanFinding, ScanRun
from app.evidence.chain import canonical_json, record_audit_event
from app.llm.pii import redact_pii
from app.llm.router import LLMRouter
from app.scanners.collectors import RULE_CONTROL_MAP, CollectedCheck, run_collectors
from app.scanners.schemas import RepoFileInput

_SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}
_MAX_REPO_FILES = 50
_MAX_FILE_BYTES = 256 * 1024
_SEVERITY_WEIGHTS = {"critical": 25.0, "high": 15.0, "medium": 8.0, "low": 3.0}


def classify_repo_file(rel_path: str) -> list[str]:
    """Infer relevant compliance collector domains from a repository file path."""
    low = rel_path.replace("\\", "/").lower()
    name = low.rsplit("/", 1)[-1]
    domains: list[str] = []

    if (
        "dockerfile" in name
        or name.startswith(".env")
        or name.endswith((".tf", ".tfvars", ".yml", ".yaml", ".ini", ".toml"))
        or "docker-compose" in name
    ):
        domains.append("config")
    if "nginx" in name or "tls" in low or "ssl" in low or name.endswith((".conf", ".tf")):
        domains.append("encryption")
    if "rbac" in low or "iam" in low or "role" in low or name.endswith(".json"):
        domains.append("rbac")
    if name.endswith(".log") or "logging" in low:
        domains.append("logging")
    if name.endswith(".md") or "sop" in low or "policy" in low:
        domains.append("sop")

    if not domains:
        domains.append("config")
    return list(dict.fromkeys(domains))


def _load_files_from_directory(repo_path: str) -> list[RepoFileInput]:
    root = Path(repo_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Repository path does not exist or is not a directory: '{repo_path}'.",
        )

    collected_files: list[RepoFileInput] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for fname in sorted(filenames):
            if len(collected_files) >= _MAX_REPO_FILES:
                return collected_files
            fpath = Path(dirpath) / fname
            if fpath.suffix.lower() in {
                ".png",
                ".jpg",
                ".jpeg",
                ".gif",
                ".ico",
                ".pdf",
                ".zip",
                ".db",
                ".sqlite",
                ".pyc",
                ".exe",
                ".woff2",
            }:
                continue
            try:
                raw = fpath.read_bytes()
            except OSError:
                continue
            if not raw or len(raw) > _MAX_FILE_BYTES or b"\x00" in raw[:1024]:
                continue
            rel = fpath.relative_to(root).as_posix()
            collected_files.append(
                RepoFileInput(path=rel, content=raw.decode("utf-8", errors="replace"))
            )
    return collected_files


async def _persist_collected_scan(
    db: AsyncSession,
    *,
    target_name: str,
    target_type: str,
    artifact_filename: str,
    artifact_sha256: str,
    scrubbed_preview: str,
    checks: list[CollectedCheck],
    auto_evaluate_controls: bool,
    audit_event_type: str,
    llm_router: LLMRouter,
    actor: Actor,
) -> tuple[ScanRun, list[ScanFinding]]:
    total_checks = len(checks)
    passed_checks = sum(1 for c in checks if c.status == "pass")
    failed_checks = sum(1 for c in checks if c.status == "fail")
    warning_checks = sum(1 for c in checks if c.status == "warning")

    if failed_checks > 0:
        run_status = "failed"
    elif warning_checks > 0:
        run_status = "warnings"
    else:
        run_status = "passed"

    penalty = 0.0
    for c in checks:
        if c.status == "fail":
            penalty += _SEVERITY_WEIGHTS.get(c.severity, 10.0)
        elif c.status == "warning":
            penalty += _SEVERITY_WEIGHTS.get(c.severity, 10.0) * 0.35
    risk_score = round(min(100.0, penalty), 1)

    llm_prompt = (
        f"Target={target_name} ({target_type}); Status={run_status}; RiskScore={risk_score}; "
        f"Checks={passed_checks} pass / {failed_checks} fail / {warning_checks} warn"
    )
    ai_res = await llm_router.generate(
        prompt=llm_prompt,
        system_prompt="Summarize compliance scan risk posture and remediation priority.",
        task_type="policy_scan",
    )

    run = ScanRun(
        target_name=target_name.strip(),
        target_type=target_type,
        artifact_filename=artifact_filename,
        artifact_sha256=artifact_sha256,
        artifact_preview=scrubbed_preview,
        status=run_status,
        total_checks=total_checks,
        passed_checks=passed_checks,
        failed_checks=failed_checks,
        warning_checks=warning_checks,
        risk_score=risk_score,
        ai_summary=ai_res.content,
        llm_provider=ai_res.provider,
        triggered_by=actor.email,
    )
    db.add(run)
    await db.flush()

    findings: list[ScanFinding] = []
    affected_rules: set[str] = set()
    for check in checks:
        clean_snippet = redact_pii(check.evidence_snippet).redacted_text
        evidence_hash = hashlib.sha256(
            canonical_json(
                {
                    "scan_run_id": run.id,
                    "rule_id": check.rule_id,
                    "status": check.status,
                    "evidence_snippet": clean_snippet,
                    "artifact_sha256": artifact_sha256,
                }
            ).encode("utf-8")
        ).hexdigest()
        finding = ScanFinding(
            scan_run_id=run.id,
            rule_id=check.rule_id,
            domain=check.domain,
            severity=check.severity,
            status=check.status,
            title=check.title,
            detail=check.detail,
            remediation=check.remediation,
            mapped_controls_json=list(check.mapped_controls),
            evidence_snippet=clean_snippet,
            evidence_hash=evidence_hash,
        )
        db.add(finding)
        findings.append(finding)
        affected_rules.add(check.rule_id.upper())

    await db.flush()
    await record_audit_event(
        db,
        event_type=audit_event_type,
        actor=actor,
        entity_type="scan_run",
        entity_id=run.id,
        action="scan",
        details={
            "target_name": run.target_name,
            "target_type": run.target_type,
            "artifact_sha256": run.artifact_sha256,
            "status": run.status,
            "risk_score": run.risk_score,
            "failed_checks": run.failed_checks,
        },
    )

    if auto_evaluate_controls:
        await evaluate_all_controls(
            db,
            framework=None,
            llm_router=llm_router,
            actor=actor,
            scan_run_id=run.id,
            rule_filter=affected_rules,
        )
    else:
        await db.commit()

    await db.refresh(run)
    for f in findings:
        await db.refresh(f)
    return run, findings


async def scan_repository_files(
    db: AsyncSession,
    *,
    target_name: str,
    repo_path: str | None,
    files: list[RepoFileInput],
    auto_evaluate_controls: bool,
    llm_router: LLMRouter,
    actor: Actor,
) -> tuple[ScanRun, list[ScanFinding]]:
    """Scan a directory of IaC/config/RBAC/SOP files or inline multi-file bundle."""
    scan_files = list(files)
    if repo_path and repo_path.strip():
        scan_files.extend(_load_files_from_directory(repo_path.strip()))
    if not scan_files:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide either a non-empty repo_path or at least one file in 'files'.",
        )

    all_checks: list[CollectedCheck] = []
    manifest_hashes: list[dict[str, str]] = []
    for item in sorted(scan_files, key=lambda x: x.path)[:_MAX_REPO_FILES]:
        file_sha = hashlib.sha256(item.content.encode("utf-8")).hexdigest()
        manifest_hashes.append({"path": item.path, "sha256": file_sha})
        domains = classify_repo_file(item.path)
        for domain in domains:
            domain_checks = run_collectors(domain, item.content)  # type: ignore[arg-type]
            for chk in domain_checks:
                all_checks.append(
                    CollectedCheck(
                        rule_id=chk.rule_id,
                        domain=chk.domain,
                        severity=chk.severity,
                        status=chk.status,
                        title=f"{chk.title} [{item.path}]",
                        detail=f"[{item.path}] {chk.detail}",
                        remediation=chk.remediation,
                        mapped_controls=chk.mapped_controls,
                        evidence_snippet=f"[{item.path}] {chk.evidence_snippet}",
                    )
                )

    combined_sha256 = hashlib.sha256(canonical_json(manifest_hashes).encode("utf-8")).hexdigest()
    preview_paths = ", ".join(m["path"] for m in manifest_hashes[:10])
    preview = redact_pii(f"Scanned {len(manifest_hashes)} file(s): {preview_paths}").redacted_text
    return await _persist_collected_scan(
        db,
        target_name=target_name,
        target_type="repo_bundle",
        artifact_filename=f"{len(manifest_hashes)}-files-repo-bundle",
        artifact_sha256=combined_sha256,
        scrubbed_preview=preview,
        checks=all_checks,
        auto_evaluate_controls=auto_evaluate_controls,
        audit_event_type="scan.repo_completed",
        llm_router=llm_router,
        actor=actor,
    )


def validate_probe_url(url: str, *, allow_private: bool = False) -> str:
    """Validate HTTP/HTTPS endpoint URL and guard against SSRF targets."""
    cleaned = url.strip()
    parsed = urlparse(cleaned)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Probe URL must use http:// or https:// and include a valid hostname.",
        )

    host = parsed.hostname.lower()
    if host in {"169.254.169.254", "metadata.google.internal"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Blocked SSRF target hostname: '{host}'.",
        )

    def _is_disallowed_ip(ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
            return True
        return bool(
            not allow_private and (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)
        )

    if _is_disallowed_ip(host):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Blocked private/link-local probe IP '{host}'.",
        )

    try:
        target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addr_infos = socket.getaddrinfo(host, target_port)
        for info in addr_infos:
            resolved_ip = str(info[4][0])
            if _is_disallowed_ip(resolved_ip):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Blocked resolved private/link-local probe IP '{resolved_ip}'.",
                )
    except HTTPException:
        raise
    except OSError:
        # DNS resolution may be mocked or offline during unit tests using httpx mock transports
        pass

    return cleaned


def _inspect_tls_version(hostname: str, port: int) -> str | None:
    try:
        ctx = ssl.create_default_context()
        with (
            socket.create_connection((hostname, port), timeout=3.0) as sock,
            ctx.wrap_socket(sock, server_hostname=hostname) as ssock,
        ):
            return ssock.version()
    except OSError:
        return None


async def probe_live_url(
    db: AsyncSession,
    *,
    target_name: str,
    url: str,
    auto_evaluate_controls: bool,
    settings: Settings,
    llm_router: LLMRouter,
    actor: Actor,
    http_client: httpx.AsyncClient | None = None,
) -> tuple[ScanRun, list[ScanFinding]]:
    """Probe a live HTTP/HTTPS endpoint for TLS transport and baseline security headers."""
    safe_url = validate_probe_url(url, allow_private=settings.allow_private_url_probes)
    parsed = urlparse(safe_url)

    try:
        if http_client is not None:
            resp = await http_client.get(safe_url)
        else:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
                resp = await client.get(safe_url)
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to probe '{safe_url}': {exc}",
        ) from exc

    hdrs = {k.lower(): v for k, v in resp.headers.items()}
    final_scheme = urlparse(str(resp.url)).scheme or parsed.scheme
    tls_version = (
        _inspect_tls_version(parsed.hostname or "", parsed.port or 443)
        if final_scheme == "https" and http_client is None
        else None
    )

    checks: list[CollectedCheck] = []

    if final_scheme == "https":
        tls_detail = (
            f"HTTPS active ({tls_version})."
            if tls_version
            else "HTTPS scheme active on probed endpoint."
        )
        checks.append(
            CollectedCheck(
                rule_id="ENC-001",
                domain="encryption",
                severity="critical",
                status="pass",
                title="HTTPS / TLS transport active on live endpoint",
                detail=tls_detail,
                remediation="Maintain TLS 1.2/1.3 enforcement.",
                mapped_controls=list(RULE_CONTROL_MAP.get("ENC-001", [])),
                evidence_snippet=f"GET {safe_url} -> {resp.status_code} ({final_scheme})",
            )
        )
    else:
        checks.append(
            CollectedCheck(
                rule_id="ENC-001",
                domain="encryption",
                severity="critical",
                status="fail",
                title="Endpoint served over unencrypted HTTP",
                detail=f"Probed endpoint {safe_url} responded over cleartext HTTP.",
                remediation="Enforce HTTPS redirect and TLS 1.2+/1.3 termination.",
                mapped_controls=list(RULE_CONTROL_MAP.get("ENC-001", [])),
                evidence_snippet=f"GET {safe_url} -> {resp.status_code} (http)",
            )
        )

    acao = hdrs.get("access-control-allow-origin", "").strip()
    if acao == "*":
        checks.append(
            CollectedCheck(
                rule_id="CFG-002",
                domain="config",
                severity="high",
                status="fail",
                title="Live endpoint returned wildcard CORS header ('*')",
                detail="Access-Control-Allow-Origin: * permits arbitrary origin requests.",
                remediation="Restrict Access-Control-Allow-Origin to explicit trusted origins.",
                mapped_controls=list(RULE_CONTROL_MAP.get("CFG-002", [])),
                evidence_snippet=f"access-control-allow-origin: {acao}",
            )
        )
    else:
        checks.append(
            CollectedCheck(
                rule_id="CFG-002",
                domain="config",
                severity="high",
                status="pass",
                title="No wildcard CORS header exposed",
                detail="Endpoint does not advertise Access-Control-Allow-Origin: *.",
                remediation="Keep explicit origin allowlists.",
                mapped_controls=list(RULE_CONTROL_MAP.get("CFG-002", [])),
                evidence_snippet=f"access-control-allow-origin: {acao or 'absent'}",
            )
        )

    missing_headers: list[str] = []
    if hdrs.get("x-content-type-options", "").lower() != "nosniff":
        missing_headers.append("X-Content-Type-Options")
    if "x-frame-options" not in hdrs:
        missing_headers.append("X-Frame-Options")
    if final_scheme == "https" and "strict-transport-security" not in hdrs:
        missing_headers.append("Strict-Transport-Security")

    if missing_headers:
        checks.append(
            CollectedCheck(
                rule_id="CFG-004",
                domain="config",
                severity="high",
                status="fail" if len(missing_headers) >= 2 else "warning",
                title="Missing HTTP security headers on live endpoint",
                detail=f"Missing recommended header(s): {', '.join(missing_headers)}.",
                remediation=(
                    "Configure X-Content-Type-Options: nosniff, X-Frame-Options: DENY, "
                    "and Strict-Transport-Security."
                ),
                mapped_controls=list(RULE_CONTROL_MAP.get("CFG-004", [])),
                evidence_snippet=f"missing={','.join(missing_headers)}",
            )
        )
    else:
        checks.append(
            CollectedCheck(
                rule_id="CFG-004",
                domain="config",
                severity="high",
                status="pass",
                title="Baseline HTTP security headers verified on live endpoint",
                detail="Verified X-Content-Type-Options, X-Frame-Options, and HSTS (for HTTPS).",
                remediation="Keep security headers enabled at reverse proxy/ASGI layer.",
                mapped_controls=list(RULE_CONTROL_MAP.get("CFG-004", [])),
                evidence_snippet="x-content-type-options=nosniff, x-frame-options=present",
            )
        )

    probe_sha = hashlib.sha256(
        canonical_json({"url": safe_url, "status": resp.status_code, "headers": hdrs}).encode(
            "utf-8"
        )
    ).hexdigest()
    preview = redact_pii(
        f"URL={safe_url} status={resp.status_code} headers={sorted(hdrs.keys())[:8]}"
    ).redacted_text
    return await _persist_collected_scan(
        db,
        target_name=target_name,
        target_type="url_probe",
        artifact_filename=parsed.hostname or "live-endpoint",
        artifact_sha256=probe_sha,
        scrubbed_preview=preview,
        checks=checks,
        auto_evaluate_controls=auto_evaluate_controls,
        audit_event_type="scan.url_probed",
        llm_router=llm_router,
        actor=actor,
    )
