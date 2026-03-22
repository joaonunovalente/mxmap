import asyncio
import json
import re
import time
import unicodedata
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mail_sovereignty.classify import classify, detect_gateway
from mail_sovereignty.constants import CONCURRENCY
from mail_sovereignty.dns import (
    lookup_autodiscover,
    lookup_mx,
    lookup_spf,
    resolve_mx_asns,
    resolve_mx_cnames,
    resolve_spf_asns,
    resolve_spf_includes,
)


def url_to_domain(url: str | None) -> str | None:
    """Extract the base domain from a URL."""
    if not url:
        return None
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or ""
    if host.startswith("www."):
        host = host[4:]
    return host if host else None


def guess_domains(name: str) -> list[str]:
    """Generate a small set of plausible .pt domain guesses for a municipality."""
    raw = name.lower().strip()
    raw = re.sub(r"\s*\(.*?\)\s*", "", raw)

    def slugify(s):
        s = re.sub(r"['\u2019`]", "", s)
        s = re.sub(r"[^a-z0-9]+", "-", s)
        return s.strip("-")

    slug = slugify(raw)
    candidates = set()
    if slug:
        candidates.add(f"{slug}.pt")
        candidates.add(f"cm-{slug}.pt")
        candidates.add(f"cm{slug}.pt")
        candidates.add(f"municipio-{slug}.pt")
        candidates.add(f"municipio{slug}.pt")
    return sorted(candidates)


def normalize_municipality_name(name: str) -> str:
    """Normalize municipality names for robust cross-file matching."""
    folded = unicodedata.normalize("NFD", name)
    folded = "".join(ch for ch in folded if unicodedata.category(ch) != "Mn")
    return re.sub(r"[^a-z0-9]+", " ", folded.lower()).strip()


async def fetch_municipalities() -> dict[str, dict[str, str]]:
    """Load Portuguese municipalities from websites.json."""
    websites_path = Path("websites.json")
    geojson_path = Path("municipalities-portugal.geojson")
    print(f"Loading municipalities from {websites_path}...")

    with websites_path.open(encoding="utf-8") as f:
        rows = json.load(f)

    with geojson_path.open(encoding="utf-8") as f:
        geo = json.load(f)

    code_by_name: dict[str, str] = {}
    district_by_code: dict[str, str] = {}
    for feature in geo.get("features", []):
        props = feature.get("properties", {})
        con_code = str(props.get("con_code", "")).strip()
        con_name = str(
            props.get("con_name_lower") or props.get("con_name") or ""
        ).strip()
        dis_name = str(props.get("dis_name", "")).strip()
        if not con_code or not con_name:
            continue
        normalized = normalize_municipality_name(con_name)
        code_by_name[normalized] = con_code
        if dis_name:
            district_by_code[con_code] = dis_name

    # Disambiguation for municipality names qualified by region in websites.json.
    alias_code_by_name: dict[str, str] = {
        normalize_municipality_name("Calheta (Açores)"): "4501",  # Calheta de Sao Jorge
        normalize_municipality_name("Calheta (Madeira)"): "3101",
        normalize_municipality_name("Lagoa (Açores)"): "4201",
        normalize_municipality_name("Lagoa (Algarve)"): "0806",
    }

    municipalities: dict[str, dict[str, str]] = {}
    duplicate_counter: dict[str, int] = {}
    unmatched: list[str] = []

    for row in rows:
        name = str(row.get("municipio", "")).strip()
        domain = str(row.get("dominio", "")).strip().lower()
        if not name:
            continue

        normalized_name = normalize_municipality_name(name)
        con_code = code_by_name.get(normalized_name, "")
        if not con_code:
            con_code = alias_code_by_name.get(normalized_name, "")
        base_id = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "municipio"
        muni_id_base = con_code or base_id
        count = duplicate_counter.get(muni_id_base, 0)
        duplicate_counter[muni_id_base] = count + 1
        muni_id = f"{muni_id_base}-{count + 1}" if count else muni_id_base

        website = f"https://{domain}" if domain else ""

        municipalities[muni_id] = {
            "cbs": muni_id,
            "con_code": con_code,
            "municipio": name,
            "name": name,
            "website": website,
            "province": district_by_code.get(con_code, ""),
        }

        if not con_code:
            unmatched.append(name)

    print(
        f"  Loaded {len(municipalities)} municipalities, "
        f"{sum(1 for m in municipalities.values() if m['website'])} with websites"
    )
    if unmatched:
        preview = ", ".join(unmatched[:8])
        suffix = "..." if len(unmatched) > 8 else ""
        print(
            f"  Warning: {len(unmatched)} municipalities without con_code match: {preview}{suffix}"
        )
    return municipalities


async def scan_municipality(
    m: dict[str, str], semaphore: asyncio.Semaphore
) -> dict[str, Any]:
    """Scan a single municipality for email provider info."""
    async with semaphore:
        domain = url_to_domain(m.get("website", ""))
        mx, spf = [], ""

        _NULL_MX = {"localhost", ""}

        if domain:
            mx = await lookup_mx(domain)
            mx = [h for h in mx if h not in _NULL_MX]
            if mx:
                spf = await lookup_spf(domain)

        if not mx:
            for guess in guess_domains(m["name"]):
                if guess == domain:
                    continue
                mx = await lookup_mx(guess)
                mx = [h for h in mx if h not in _NULL_MX]
                if mx:
                    domain = guess
                    spf = await lookup_spf(guess)
                    break

        spf_resolved = await resolve_spf_includes(spf) if spf else ""
        spf_asns = (
            await resolve_spf_asns(spf_resolved or spf)
            if (spf_resolved or spf)
            else set()
        )
        mx_cnames = await resolve_mx_cnames(mx) if mx else {}
        mx_asns = await resolve_mx_asns(mx) if mx else set()
        autodiscover = await lookup_autodiscover(domain) if domain else {}
        provider = classify(
            mx,
            spf,
            mx_cnames=mx_cnames,
            mx_asns=mx_asns or None,
            resolved_spf=spf_resolved or None,
            autodiscover=autodiscover or None,
            spf_asns=spf_asns or None,
        )
        gateway = detect_gateway(mx) if mx else None

        entry: dict[str, Any] = {
            "cbs": m["cbs"],
            "con_code": m.get("con_code", ""),
            "municipio": m.get("municipio", m["name"]),
            "name": m["name"],
            "province": m.get("province", ""),
            "domain": domain or "",
            "mx": mx,
            "spf": spf,
            "provider": provider,
        }
        if spf_resolved and spf_resolved != spf:
            entry["spf_resolved"] = spf_resolved
        if gateway:
            entry["gateway"] = gateway
        if mx_cnames:
            entry["mx_cnames"] = mx_cnames
        if mx_asns:
            entry["mx_asns"] = sorted(mx_asns)
        if spf_asns:
            entry["spf_asns"] = sorted(spf_asns)
        if autodiscover:
            entry["autodiscover"] = autodiscover
        return entry


async def run(output_path: Path) -> None:
    municipalities = await fetch_municipalities()
    total = len(municipalities)

    print(f"\nScanning {total} municipalities for MX/SPF records...")
    print("(This takes a few minutes with async lookups)\n")

    semaphore = asyncio.Semaphore(CONCURRENCY)
    tasks = [scan_municipality(m, semaphore) for m in municipalities.values()]

    results = {}
    done = 0
    for coro in asyncio.as_completed(tasks):
        result = await coro
        results[result["cbs"]] = result
        done += 1
        if done % 50 == 0 or done == total:
            counts = {}
            for r in results.values():
                counts[r["provider"]] = counts.get(r["provider"], 0) + 1
            print(
                f"  [{done:4d}/{total}]  "
                f"MS={counts.get('microsoft', 0)}  "
                f"Google={counts.get('google', 0)}  "
                f"AWS={counts.get('aws', 0)}  "
                f"ISP={counts.get('pt-isp', 0)}  "
                f"Indep={counts.get('independent', 0)}  "
                f"?={counts.get('unknown', 0)}"
            )

    counts = {}
    for r in results.values():
        counts[r["provider"]] = counts.get(r["provider"], 0) + 1

    print(f"\n{'=' * 50}")
    print(f"RESULTS: {len(results)} municipalities scanned")
    print(f"  Microsoft/Azure : {counts.get('microsoft', 0):>5}")
    print(f"  Google/GCP      : {counts.get('google', 0):>5}")
    print(f"  AWS             : {counts.get('aws', 0):>5}")
    print(f"  PT ISP          : {counts.get('pt-isp', 0):>5}")
    print(f"  Independent     : {counts.get('independent', 0):>5}")
    print(f"  Unknown/No MX   : {counts.get('unknown', 0):>5}")
    print(f"{'=' * 50}")

    sorted_counts = dict(sorted(counts.items()))
    sorted_munis = dict(sorted(results.items(), key=lambda kv: kv[1]["name"].lower()))

    output = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total": len(results),
        "counts": sorted_counts,
        "municipalities": sorted_munis,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=None, separators=(",", ":"))

    size_kb = len(json.dumps(output)) / 1024
    print(f"\nWritten {output_path} ({size_kb:.0f} KB)")
