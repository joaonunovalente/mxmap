from mail_sovereignty.constants import (
    AWS_SPF_HINT_KEYWORDS,
    AWS_KEYWORDS,
    PT_ISP_ASNS,
    EU_ISP_KEYWORDS,
    FOREIGN_SENDER_KEYWORDS,
    GATEWAY_KEYWORDS,
    GOOGLE_KEYWORDS,
    MAILBOX_ASNS,
    MICROSOFT_KEYWORDS,
    PT_ISP_KEYWORDS,
    PROVIDER_KEYWORDS,
    SMTP_BANNER_KEYWORDS,
    US_OTHER_KEYWORDS,
)


def classify_from_smtp_banner(banner: str, ehlo: str = "") -> str | None:
    """Classify provider from SMTP banner/EHLO. Returns provider or None."""
    if not banner and not ehlo:
        return None
    blob = f"{banner} {ehlo}".lower()
    for provider, keywords in SMTP_BANNER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return None


def classify_from_autodiscover(autodiscover: dict[str, str] | None) -> str | None:
    """Classify provider from autodiscover DNS records."""
    if not autodiscover:
        return None
    blob = " ".join(autodiscover.values()).lower()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return None


def detect_gateway(mx_records: list[str]) -> str | None:
    """Return gateway provider name if MX matches a known gateway, else None."""
    mx_blob = " ".join(mx_records).lower()
    for gateway, keywords in GATEWAY_KEYWORDS.items():
        if any(k in mx_blob for k in keywords):
            return gateway
    return None


def _check_spf_for_provider(spf_blob: str) -> str | None:
    """Check an SPF blob for hyperscaler keywords, return provider or None."""
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in spf_blob for k in keywords):
            return provider
    return None


def _classify_from_spf_asns(spf_asns: set[int] | None) -> str | None:
    """Return provider if SPF IP blocks resolve to a known mailbox-hosting ASN.

    Only Microsoft and Google are checked: their SPF IP ranges are specific to
    Exchange Online / Google Workspace.  AWS ASNs are deliberately excluded
    because Amazon SES (AS16509/14618) appears in SPF for bulk sending even
    when the actual mailbox is hosted elsewhere.
    """
    if not spf_asns:
        return None
    for provider in ("microsoft", "google"):
        if any(MAILBOX_ASNS.get(a) == provider for a in spf_asns):
            return provider
    return None


def _has_aws_spf_profile(spf_record: str | None, resolved_spf: str | None) -> bool:
    """Return True when SPF includes known AWS-backed sender profiles."""
    blob = f"{spf_record or ''} {resolved_spf or ''}".lower()
    if any(k in blob for k in AWS_KEYWORDS):
        return True
    if any(k in blob for k in AWS_SPF_HINT_KEYWORDS):
        return True
    return False


def classify(
    mx_records: list[str],
    spf_record: str | None,
    mx_cnames: dict[str, str] | None = None,
    mx_asns: set[int] | None = None,
    resolved_spf: str | None = None,
    autodiscover: dict[str, str] | None = None,
    spf_asns: set[int] | None = None,
) -> str:
    """Classify email provider based on MX, CNAME targets, SPF, and resolved IPs.

    MX records are checked first (they show where mail is actually delivered).
    CNAME targets of MX hosts are checked next (to detect hidden hyperscaler usage).
    If MX points to a known gateway, SPF (including resolved includes) is checked
    to identify the actual mailbox provider behind the gateway.
    SPF is only used as fallback when MX alone is inconclusive.
    As a last resort, ASN lookups of SPF IP blocks reveal the true provider
    even when it is hidden behind local ISP gateways or flattened SPF services.
    """
    mx_blob = " ".join(mx_records).lower()

    if any(k in mx_blob for k in MICROSOFT_KEYWORDS):
        return "microsoft"
    if any(k in mx_blob for k in GOOGLE_KEYWORDS):
        return "google"
    if any(k in mx_blob for k in AWS_KEYWORDS):
        return "aws"
    if any(k in mx_blob for k in US_OTHER_KEYWORDS):
        return "us-other"
    if any(k in mx_blob for k in PT_ISP_KEYWORDS):
        return "pt-isp"
    if any(k in mx_blob for k in EU_ISP_KEYWORDS):
        return "eu-isp"

    if mx_records and mx_cnames:
        cname_blob = " ".join(mx_cnames.values()).lower()
        if any(k in cname_blob for k in MICROSOFT_KEYWORDS):
            return "microsoft"
        if any(k in cname_blob for k in GOOGLE_KEYWORDS):
            return "google"
        if any(k in cname_blob for k in AWS_KEYWORDS):
            return "aws"
        if any(k in cname_blob for k in US_OTHER_KEYWORDS):
            return "us-other"

    if mx_records and detect_gateway(mx_records):
        spf_blob = (spf_record or "").lower()
        provider = _check_spf_for_provider(spf_blob)
        if not provider and resolved_spf:
            provider = _check_spf_for_provider(resolved_spf.lower())
        if provider:
            return provider
        # No hyperscaler in SPF — check autodiscover for backend provider
        ad_provider = classify_from_autodiscover(autodiscover)
        if ad_provider:
            return ad_provider
        # Gateway relays to independent, fall through

    if mx_records:
        if any(k in mx_blob for k in PT_ISP_KEYWORDS):
            return "pt-isp"
        if any(k in mx_blob for k in EU_ISP_KEYWORDS):
            return "eu-isp"
        if mx_asns and mx_asns & PT_ISP_ASNS.keys():
            # Check autodiscover for hyperscaler backend behind PT ISP relay
            ad_provider = classify_from_autodiscover(autodiscover)
            if ad_provider:
                return ad_provider
            # Check resolved SPF IPs for hidden hyperscaler
            spf_asn_provider = _classify_from_spf_asns(spf_asns)
            if spf_asn_provider:
                return spf_asn_provider
            return "pt-isp"
        # Check autodiscover for hyperscaler backend behind independent MX
        ad_provider = classify_from_autodiscover(autodiscover)
        if ad_provider:
            return ad_provider
        # Check resolved SPF IPs to reveal hyperscalers hidden behind gateway relays
        spf_asn_provider = _classify_from_spf_asns(spf_asns)
        if spf_asn_provider:
            return spf_asn_provider
        if spf_asns and (16509 in spf_asns or 14618 in spf_asns):
            if _has_aws_spf_profile(spf_record, resolved_spf):
                return "aws"
        return "independent"

    spf_blob = (spf_record or "").lower()
    provider = _check_spf_for_provider(spf_blob)
    if not provider and resolved_spf:
        provider = _check_spf_for_provider(resolved_spf.lower())
    if provider:
        return provider

    return "unknown"


def classify_from_mx(mx_records: list[str]) -> str | None:
    """Classify provider from MX records alone."""
    if not mx_records:
        return None
    blob = " ".join(mx_records).lower()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return "independent"


def classify_from_spf(spf_record: str | None) -> str | None:
    """Classify provider from SPF record alone."""
    if not spf_record:
        return None
    blob = spf_record.lower()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return None


def spf_mentions_providers(spf_record: str | None) -> set[str]:
    """Return set of providers mentioned in SPF (main + foreign senders)."""
    if not spf_record:
        return set()
    blob = spf_record.lower()
    found = set()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            found.add(provider)
    for provider, keywords in FOREIGN_SENDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            found.add(provider)
    return found
