"""Threat-intel enrichment from two public feeds (no API key for either):

- CISA Known Exploited Vulnerabilities (KEV): CVEs with confirmed exploitation.
- FIRST EPSS: the modelled probability that a CVE is exploited in the next 30 days.

Only CVE IDs leave the machine (in the EPSS query). No host or scan data is sent.
"""

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import date, datetime

import httpx2
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings
from .models import CveIntel, FindingCve
from .risk import recompute_risk

EPSS_MAX_CVES_PER_REQUEST = 100
EPSS_MAX_PARAM_CHARS = 2000
MAX_FEED_BYTES = 50 * 1024 * 1024
HTTP_TIMEOUT = httpx2.Timeout(30.0)
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")


class IntelError(RuntimeError):
    """A feed could not be fetched or did not look the way it should."""


@dataclass
class KevEntry:
    date_added: date | None
    due_date: date | None
    ransomware: bool


def _to_date(value: object) -> date | None:
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        return None


def _to_fraction(value: object) -> float | None:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return number if 0.0 <= number <= 1.0 else None


def _get_json(client: httpx2.Client, url: str) -> dict:
    if not url.startswith("https://"):
        raise IntelError("Feed URLs must use https.")
    try:
        response = client.get(url)
        response.raise_for_status()
        if len(response.content) > MAX_FEED_BYTES:
            raise IntelError("Feed response is larger than expected.")
        data = response.json()
    except httpx2.HTTPError as exc:
        raise IntelError(f"Could not reach {httpx2.URL(url).host}: {exc}") from exc
    except ValueError as exc:
        raise IntelError(f"{httpx2.URL(url).host} did not return JSON.") from exc
    if not isinstance(data, dict):
        raise IntelError(f"{httpx2.URL(url).host} returned an unexpected document.")
    return data


def fetch_kev(client: httpx2.Client, url: str) -> tuple[dict[str, KevEntry], str]:
    data = _get_json(client, url)
    entries: dict[str, KevEntry] = {}
    for item in data.get("vulnerabilities") or []:
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cveID", "")).strip().upper()
        if not cve:
            continue
        entries[cve] = KevEntry(
            date_added=_to_date(item.get("dateAdded")),
            due_date=_to_date(item.get("dueDate")),
            ransomware=str(item.get("knownRansomwareCampaignUse", "")).strip().lower() == "known",
        )
    return entries, str(data.get("catalogVersion", ""))


def chunk_cves(cves: Iterable[str]) -> Iterator[list[str]]:
    """Batch CVE IDs to stay inside the EPSS API's per-request limits."""
    batch: list[str] = []
    length = 0
    for cve in cves:
        added = len(cve) + (1 if batch else 0)
        if batch and (
            len(batch) >= EPSS_MAX_CVES_PER_REQUEST or length + added > EPSS_MAX_PARAM_CHARS
        ):
            yield batch
            batch, length, added = [], 0, len(cve)
        batch.append(cve)
        length += added
    if batch:
        yield batch


def fetch_epss(
    client: httpx2.Client, url: str, cves: Iterable[str]
) -> dict[str, tuple[float | None, float | None]]:
    scores: dict[str, tuple[float | None, float | None]] = {}
    # Only well-formed CVE IDs go into the query string, joined with literal commas
    # exactly as the EPSS API documents it.
    wanted = sorted({cve for cve in cves if CVE_ID.match(cve)})
    for batch in chunk_cves(wanted):
        data = _get_json(client, f"{url}?cve={','.join(batch)}")
        for row in data.get("data") or []:
            if not isinstance(row, dict):
                continue
            cve = str(row.get("cve", "")).strip().upper()
            if cve in batch:  # ignore anything we did not ask about
                scores[cve] = (_to_fraction(row.get("epss")), _to_fraction(row.get("percentile")))
    return scores


def refresh_intel(db: Session, settings: Settings, client: httpx2.Client | None = None) -> dict:
    """Pull KEV and EPSS for every CVE referenced by a finding, then rescore."""
    cves = sorted(set(db.scalars(select(FindingCve.cve_id)).all()))
    own_client = client is None
    client = client or httpx2.Client(timeout=HTTP_TIMEOUT, follow_redirects=False)

    # The feeds are independent. If one is down, still use the other and say so.
    kev: dict[str, KevEntry] | None = None
    epss: dict[str, tuple[float | None, float | None]] | None = None
    kev_version = ""
    warnings: list[str] = []
    try:
        try:
            kev, kev_version = fetch_kev(client, settings.kev_url)
        except IntelError as exc:
            warnings.append(f"CISA KEV was not updated. {exc}")
        try:
            epss = fetch_epss(client, settings.epss_url, cves) if cves else {}
        except IntelError as exc:
            warnings.append(f"EPSS was not updated. {exc}")
    finally:
        if own_client:
            client.close()
    if kev is None and epss is None:
        raise IntelError(" ".join(warnings))

    now = datetime.now()  # noqa: DTZ005
    existing = {row.cve_id: row for row in db.scalars(select(CveIntel)).all()}
    for cve in cves:
        row = existing.get(cve)
        if row is None:
            row = CveIntel(cve_id=cve, updated_at=now)
            db.add(row)
        if kev is not None:
            entry = kev.get(cve)
            row.in_kev = entry is not None
            row.kev_date_added = entry.date_added if entry else None
            row.kev_due_date = entry.due_date if entry else None
            row.kev_ransomware = entry.ransomware if entry else False
        if epss is not None and cve in epss:
            row.epss, row.epss_percentile = epss[cve]
        row.updated_at = now

    db.flush()
    rescored = recompute_risk(db)
    db.commit()
    return {
        "cves_checked": len(cves),
        "kev_catalog_version": kev_version,
        "kev_catalog_size": len(kev) if kev is not None else None,
        "kev_matches": sum(1 for cve in cves if cve in kev) if kev is not None else None,
        "epss_scores": len(epss) if epss is not None else None,
        "findings_rescored": rescored,
        "warnings": warnings,
    }
