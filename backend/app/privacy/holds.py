from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import LegalHold


def legal_hold_matches(
    hold: LegalHold,
    subject_email: str,
    data_systems: list[str],
) -> bool:
    """Return True if an active LegalHold applies to the subject email or data systems."""
    if hold.status != "active":
        return False

    normalized_email = subject_email.strip().lower()
    email_domain = normalized_email.split("@", 1)[1] if "@" in normalized_email else ""
    custodians = [str(item).strip().lower() for item in (hold.custodian_scope_json or []) if item]
    systems_hold = {str(item).strip().lower() for item in (hold.systems_scope_json or []) if item}
    systems_req = {str(item).strip().lower() for item in data_systems if item}

    custodian_match = False
    for scope in custodians:
        if scope in {"*", "all"}:
            custodian_match = True
            break
        if scope == normalized_email:
            custodian_match = True
            break
        if scope.startswith("@") and email_domain and scope[1:] == email_domain:
            custodian_match = True
            break

    if custodian_match:
        if not systems_hold or "*" in systems_hold or not systems_req:
            return True
        return bool(systems_hold & systems_req)

    if not custodians and systems_hold and systems_req:
        return bool(systems_hold & systems_req)

    return False


async def find_blocking_legal_holds(
    db: AsyncSession,
    subject_email: str,
    data_systems: list[str],
) -> list[LegalHold]:
    """Find all active legal holds that block erasure for a subject and system set."""
    stmt = select(LegalHold).where(LegalHold.status == "active").order_by(LegalHold.placed_at.asc())
    holds = list((await db.execute(stmt)).scalars().all())
    return [h for h in holds if legal_hold_matches(h, subject_email, data_systems)]
