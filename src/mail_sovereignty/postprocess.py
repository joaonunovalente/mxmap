import asyncio
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from mail_sovereignty.classify import (
    classify,
    classify_from_smtp_banner,
    detect_gateway,
)
from mail_sovereignty.constants import (
    CONCURRENCY_POSTPROCESS,
    CONCURRENCY_SMTP,
    EMAIL_RE,
    SKIP_DOMAINS,
    SUBPAGES,
    TYPO3_RE,
)
from mail_sovereignty.dns import (
    lookup_autodiscover,
    lookup_mx,
    lookup_spf,
    resolve_mx_asns,
    resolve_mx_cnames,
    resolve_spf_asns,
    resolve_spf_includes,
)
from mail_sovereignty.smtp import fetch_smtp_banner


def decrypt_typo3(encoded: str, offset: int = 2) -> str:
    """Decrypt TYPO3 linkTo_UnCryptMailto Caesar cipher.

    TYPO3 encrypts mailto: links with a Caesar shift on three ASCII ranges:
      0x2B-0x3A (+,-./0123456789:)  -- covers . : and digits
      0x40-0x5A (@A-Z)             -- covers @ and uppercase
      0x61-0x7A (a-z)             -- covers lowercase
    Default encryption offset is -2, so decryption is +2 with wrap.
    """
    ranges = [(0x2B, 0x3A), (0x40, 0x5A), (0x61, 0x7A)]
    result = []
    for c in encoded:
        code = ord(c)
        decrypted = False
        for start, end in ranges:
            if start <= code <= end:
                n = code + offset
                if n > end:
                    n = start + (n - end - 1)
                result.append(chr(n))
                decrypted = True
                break
        if not decrypted:
            result.append(c)
    return "".join(result)


def extract_email_domains(html: str) -> set[str]:
    """Extract email domains from HTML, including TYPO3-obfuscated emails."""
    domains = set()

    for email in EMAIL_RE.findall(html):
        domain = email.split("@")[1].lower()
        if domain not in SKIP_DOMAINS:
            domains.add(domain)

    for email in __import__("re").findall(r'mailto:([^">\s?]+)', html):
        if "@" in email:
            domain = email.split("@")[1].lower()
            if domain not in SKIP_DOMAINS:
                domains.add(domain)

    for encoded in TYPO3_RE.findall(html):
        decoded = decrypt_typo3(encoded)
        decoded = decoded.replace("mailto:", "")
        if "@" in decoded:
            domain = decoded.split("@")[1].lower()
            if domain not in SKIP_DOMAINS:
                domains.add(domain)

    return domains


def build_urls(domain: str) -> list[str]:
    """Build candidate URLs to scrape, trying www. prefix first."""
    domain = domain.strip()
    if domain.startswith(("http://", "https://")):
        parsed = urlparse(domain)
        domain = parsed.hostname or domain
    if domain.startswith("www."):
        bare = domain[4:]
    else:
        bare = domain

    bases = [f"https://www.{bare}", f"https://{bare}"]
    urls = []
    for base in bases:
        urls.append(base + "/")
        for path in SUBPAGES:
            urls.append(base + path)
    return urls


async def scrape_email_domains(client: httpx.AsyncClient, domain: str) -> set[str]:
    """Scrape a municipality website for email domains."""
    if not domain:
        return set()

    all_domains = set()
    urls = build_urls(domain)

    for url in urls:
        try:
            r = await client.get(url, follow_redirects=True, timeout=15)
            if r.status_code != 200:
                continue
            domains = extract_email_domains(r.text)
            all_domains |= domains
            if all_domains:
                return all_domains
        except Exception:
            continue

    return all_domains


async def process_unknown(
    client: httpx.AsyncClient, semaphore: asyncio.Semaphore, m: dict[str, Any]
) -> dict[str, Any]:
    """Try to resolve an unknown municipality by scraping its website."""
    async with semaphore:
        cbs = m["cbs"]
        name = m["name"]
        domain = m.get("domain", "")

        if not domain:
            print(f"  SKIP     {cbs:>8} {name:<30} (no domain)")
            return m

        email_domains = await scrape_email_domains(client, domain)

        for email_domain in sorted(email_domains):
            mx = await lookup_mx(email_domain)
            if mx:
                spf = await lookup_spf(email_domain)
                spf_resolved = await resolve_spf_includes(spf) if spf else ""
                mx_cnames = await resolve_mx_cnames(mx)
                mx_asns = await resolve_mx_asns(mx)
                autodiscover = await lookup_autodiscover(email_domain)
                provider = classify(
                    mx,
                    spf,
                    mx_cnames=mx_cnames,
                    mx_asns=mx_asns or None,
                    resolved_spf=spf_resolved or None,
                    autodiscover=autodiscover or None,
                )
                gateway = detect_gateway(mx)
                print(
                    f"  RESOLVED {cbs:>8} {name:<30} "
                    f"email_domain={email_domain} -> {provider}"
                )
                m["mx"] = mx
                m["spf"] = spf
                m["provider"] = provider
                m["domain"] = email_domain
                if spf_resolved and spf_resolved != spf:
                    m["spf_resolved"] = spf_resolved
                if gateway:
                    m["gateway"] = gateway
                if mx_cnames:
                    m["mx_cnames"] = mx_cnames
                if mx_asns:
                    m["mx_asns"] = sorted(mx_asns)
                if autodiscover:
                    m["autodiscover"] = autodiscover
                return m

        print(
            f"  UNKNOWN  {cbs:>8} {name:<30} "
            f"(scraped email domains: {email_domains or 'none'})"
        )
        return m


MANUAL_OVERRIDES: dict = {
    "0615": {"provider": "pt-isp", "spf_asns": []},  # Soure
    "1505": {"provider": "us-other", "spf_asns": []},  # Grândola
    "1504": {"provider": "us-other", "spf_asns": []},  # Barreiro
    "0311": {"provider": "pt-isp", "spf_asns": []},  # Vieira do Minho
    "0305": {"provider": "eu-isp", "spf_asns": []},  # Celorico de Basto 1709
    "1709": {"provider": "microsoft", "spf_asns": []},  # Ribeira de Pena
    "0506": {"provider": "pt-isp", "spf_asns": []},  # Oleiros
    "0310": {"provider": "pt-isp", "spf_asns": []},  # Terras de Bouro
    "0206": {"provider": "us-other", "spf_asns": []},  # Castro Verde
    "3104": {"provider": "pt-isp", "spf_asns": []},  # Machico
    "0103": {"provider": "us-other", "spf_asns": []},  # Anadia
    "0119": {"provider": "pt-isp", "spf_asns": []},  # Vale de Cambra
    "0112": {"provider": "pt-isp", "spf_asns": []},  # Murtosa
    "0906": {"provider": "us-other", "spf_asns": []},  # Gouveia
    "1823": {"provider": "us-other", "spf_asns": []},  # Viseu
    "1812": {"provider": "us-other", "spf_asns": []},  # Penedono
    "0304": {"provider": "us-other", "spf_asns": []},  # Cabeceiras de Basto
}


async def run(data_path: Path) -> None:
    with open(data_path, encoding="utf-8") as f:
        data = json.load(f)

    muni = data["municipalities"]

    # Step 1: Apply manual overrides
    print("Applying manual overrides...")
    dns_relookup = []  # (cbs, domain) pairs needing MX/SPF re-lookup
    locked_overrides: set[str] = set()
    for cbs, override in MANUAL_OVERRIDES.items():
        if cbs not in muni and "name" in override:
            muni[cbs] = {
                "cbs": cbs,
                "name": override["name"],
                "province": override.get("province", ""),
                "domain": "",
                "mx": [],
                "spf": "",
                "provider": "unknown",
            }
            print(f"  {cbs:>8} {override['name']:<30} (added missing municipality)")
        if cbs not in muni:
            continue
        if cbs in muni:
            if "domain" in override:
                muni[cbs]["domain"] = override["domain"]
            if "provider" in override:
                muni[cbs]["provider"] = override["provider"]
                locked_overrides.add(cbs)
            if "gateway" in override:
                muni[cbs]["gateway"] = override["gateway"]
            if "mx" in override:
                muni[cbs]["mx"] = override["mx"]
            if "spf" in override:
                muni[cbs]["spf"] = override["spf"]
            if "spf_asns" in override:
                muni[cbs]["spf_asns"] = override["spf_asns"]
            if "mx_asns" in override:
                muni[cbs]["mx_asns"] = override["mx_asns"]
            if override.get("provider") == "merged":
                muni[cbs]["mx"] = []
                muni[cbs]["spf"] = ""
            # Domain-only override: need to re-lookup MX/SPF from DNS
            if (
                "domain" in override
                and override["domain"]
                and "mx" not in override
                and "provider" not in override
            ):
                dns_relookup.append((cbs, override["domain"]))
            else:
                print(
                    f"  {cbs:>8} {muni[cbs]['name']:<30} -> {override.get('provider', '?')}"
                )

    if dns_relookup:

        async def _relookup(cbs, domain):
            mx = await lookup_mx(domain)
            spf = await lookup_spf(domain)
            spf_resolved = await resolve_spf_includes(spf) if spf else ""
            mx_cnames = await resolve_mx_cnames(mx) if mx else {}
            mx_asns = await resolve_mx_asns(mx) if mx else set()
            autodiscover = await lookup_autodiscover(domain)
            provider = classify(
                mx,
                spf,
                mx_cnames=mx_cnames,
                mx_asns=mx_asns or None,
                resolved_spf=spf_resolved or None,
                autodiscover=autodiscover or None,
            )
            gateway = detect_gateway(mx) if mx else None
            return (
                cbs,
                mx,
                spf,
                spf_resolved,
                mx_cnames,
                mx_asns,
                provider,
                gateway,
                autodiscover,
            )

        results = await asyncio.gather(*[_relookup(c, d) for c, d in dns_relookup])
        for (
            cbs,
            mx,
            spf,
            spf_resolved,
            mx_cnames,
            mx_asns,
            provider,
            gateway,
            autodiscover,
        ) in results:
            muni[cbs]["mx"] = mx
            muni[cbs]["spf"] = spf
            muni[cbs]["provider"] = provider
            if spf_resolved and spf_resolved != spf:
                muni[cbs]["spf_resolved"] = spf_resolved
            if gateway:
                muni[cbs]["gateway"] = gateway
            if mx_cnames:
                muni[cbs]["mx_cnames"] = mx_cnames
            if mx_asns:
                muni[cbs]["mx_asns"] = sorted(mx_asns)
            if autodiscover:
                muni[cbs]["autodiscover"] = autodiscover
            print(f"  {cbs:>8} {muni[cbs]['name']:<30} -> {provider} (DNS re-lookup)")

    # Step 2: Retry DNS for unknowns that have a domain
    dns_retry_candidates = [
        m
        for m in muni.values()
        if m["provider"] == "unknown"
        and m.get("domain")
        and m["cbs"] not in locked_overrides
    ]
    if dns_retry_candidates:
        print(f"\nRetrying DNS for {len(dns_retry_candidates)} unknown domains...")
        for m in dns_retry_candidates:
            mx = await lookup_mx(m["domain"])
            if mx:
                spf = await lookup_spf(m["domain"])
                spf_resolved = await resolve_spf_includes(spf) if spf else ""
                mx_cnames = await resolve_mx_cnames(mx)
                mx_asns = await resolve_mx_asns(mx)
                autodiscover = await lookup_autodiscover(m["domain"])
                provider = classify(
                    mx,
                    spf,
                    mx_cnames=mx_cnames,
                    mx_asns=mx_asns or None,
                    resolved_spf=spf_resolved or None,
                    autodiscover=autodiscover or None,
                )
                gateway = detect_gateway(mx)
                m["mx"] = mx
                m["spf"] = spf
                m["provider"] = provider
                if spf_resolved and spf_resolved != spf:
                    m["spf_resolved"] = spf_resolved
                if gateway:
                    m["gateway"] = gateway
                if mx_cnames:
                    m["mx_cnames"] = mx_cnames
                if mx_asns:
                    m["mx_asns"] = sorted(mx_asns)
                if autodiscover:
                    m["autodiscover"] = autodiscover
                print(f"  RECOVERED {m['cbs']:>8} {m['name']:<30} -> {provider}")

    # Step 2.5: SMTP banner check for independent/unknown with MX records
    smtp_candidates = [
        m
        for m in muni.values()
        if m["provider"] in ("independent", "unknown")
        and m.get("mx")
        and m["cbs"] not in locked_overrides
    ]
    if smtp_candidates:
        # Deduplicate: map each unique MX host -> list of CBS codes
        mx_host_to_cbs: dict[str, list[str]] = {}
        for m in smtp_candidates:
            primary_mx = m["mx"][0]
            mx_host_to_cbs.setdefault(primary_mx, []).append(m["cbs"])

        print(
            f"\nSMTP banner check: {len(smtp_candidates)} entries, "
            f"{len(mx_host_to_cbs)} unique MX hosts..."
        )
        smtp_semaphore = asyncio.Semaphore(CONCURRENCY_SMTP)

        async def _fetch_banner(mx_host: str) -> tuple[str, dict[str, str]]:
            async with smtp_semaphore:
                res = await fetch_smtp_banner(mx_host)
                return mx_host, res

        banner_results = await asyncio.gather(
            *[_fetch_banner(host) for host in mx_host_to_cbs]
        )

        smtp_reclassified = 0
        for mx_host, result in banner_results:
            banner = result.get("banner", "")
            ehlo = result.get("ehlo", "")
            if not banner:
                continue
            provider = classify_from_smtp_banner(banner, ehlo)
            for cbs in mx_host_to_cbs[mx_host]:
                muni[cbs]["smtp_banner"] = banner
                if provider and muni[cbs]["provider"] in ("independent", "unknown"):
                    old = muni[cbs]["provider"]
                    muni[cbs]["provider"] = provider
                    smtp_reclassified += 1
                    print(
                        f"  SMTP     {cbs:>8} {muni[cbs]['name']:<30} "
                        f"{old} -> {provider} ({mx_host})"
                    )

        print(f"  SMTP reclassified: {smtp_reclassified}")

    # Step 3: Scrape remaining unknowns
    unknowns = [
        m
        for m in muni.values()
        if m["provider"] == "unknown" and m["cbs"] not in locked_overrides
    ]
    print(f"\n{len(unknowns)} unknown municipalities to investigate\n")

    if unknowns:
        semaphore = asyncio.Semaphore(CONCURRENCY_POSTPROCESS)
        async with httpx.AsyncClient(
            headers={
                "User-Agent": "mxmap.nl/1.0 (https://codeberg.org/joaonunovalente/mxmap-pt)"
            },
            follow_redirects=True,
        ) as client:
            tasks = [process_unknown(client, semaphore, m) for m in unknowns]
            results = await asyncio.gather(*tasks)

        resolved = 0
        for m in results:
            muni[m["cbs"]] = m
            if m["provider"] != "unknown":
                resolved += 1
        print(f"\nResolved {resolved}/{len(unknowns)} via scraping")

    # Step 4: Enrich spf_asns for entries that have SPF text but no spf_asns yet
    missing_spf_asns = [
        m
        for m in muni.values()
        if (m.get("spf_resolved") or m.get("spf")) and "spf_asns" not in m
    ]
    if missing_spf_asns:
        print(
            f"\nResolving SPF IP blocks for {len(missing_spf_asns)} municipalities..."
        )
        sem = asyncio.Semaphore(CONCURRENCY_POSTPROCESS)

        async def _enrich_spf_asns(m: dict) -> None:
            async with sem:
                spf_text = m.get("spf_resolved") or m.get("spf", "")
                asns = await resolve_spf_asns(spf_text)
                if asns:
                    m["spf_asns"] = sorted(asns)

        await asyncio.gather(*[_enrich_spf_asns(m) for m in missing_spf_asns])
        enriched = sum(1 for m in missing_spf_asns if "spf_asns" in m)
        print(f"  Enriched {enriched} municipalities with SPF ASNs")

    # Step 5: Re-classify entries that have spf_asns but may have been classified
    # without that signal (e.g., independent MX via local gateway hiding Microsoft)
    reclassified_spf = 0
    for m in muni.values():
        if m["cbs"] in locked_overrides:
            continue
        if m["provider"] not in ("independent", "pt-isp", "unknown"):
            continue
        spf_asns_set = set(m.get("spf_asns", []))
        if not spf_asns_set:
            continue
        new_provider = classify(
            m["mx"],
            m["spf"],
            mx_asns=set(m.get("mx_asns", [])) or None,
            resolved_spf=m.get("spf_resolved") or None,
            autodiscover=m.get("autodiscover") or None,
            spf_asns=spf_asns_set,
        )
        if new_provider != m["provider"]:
            print(
                f"  SPF-IP  {m['cbs']:>8} {m['name']:<30} "
                f"{m['provider']} -> {new_provider}"
            )
            m["provider"] = new_provider
            reclassified_spf += 1
    if reclassified_spf:
        print(f"  SPF-IP reclassified: {reclassified_spf}")

    # Recompute counts
    counts = {}
    for m in muni.values():
        counts[m["provider"]] = counts.get(m["provider"], 0) + 1
    data["counts"] = dict(sorted(counts.items()))
    data["total"] = len(muni)
    data["municipalities"] = dict(sorted(muni.items(), key=lambda kv: int(kv[0][2:])))

    remaining = counts.get("unknown", 0)
    print(f"\nFinal counts: {json.dumps(counts)}")

    if remaining > 0:
        print(f"\nStill unknown ({remaining}, for manual review):")
        for m in sorted(muni.values(), key=lambda x: int(x["cbs"][2:])):
            if m["provider"] == "unknown":
                print(
                    f"  {m['cbs']:>8}  {m['name']:<30} {m['province']:<20} domain={m['domain']}"
                )

    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, separators=(",", ":"))

    print(f"\nUpdated {data_path}")
