from mail_sovereignty.constants import (
    MICROSOFT_KEYWORDS,
    GOOGLE_KEYWORDS,
    AWS_KEYWORDS,
    US_OTHER_KEYWORDS,
    PROVIDER_KEYWORDS,
    FOREIGN_SENDER_KEYWORDS,
    SKIP_DOMAINS,
    PT_ISP_ASNS,
)


def test_keyword_lists_non_empty():
    assert MICROSOFT_KEYWORDS
    assert GOOGLE_KEYWORDS
    assert AWS_KEYWORDS
    assert US_OTHER_KEYWORDS
    assert "fortimailcloud.com" in US_OTHER_KEYWORDS
    assert "fortimail.com" in US_OTHER_KEYWORDS


def test_provider_keywords_has_all_providers():
    assert set(PROVIDER_KEYWORDS.keys()) == {
        "microsoft",
        "google",
        "aws",
        "us-other",
    }


def test_foreign_sender_keywords_non_empty():
    assert FOREIGN_SENDER_KEYWORDS
    assert "mailchimp" in FOREIGN_SENDER_KEYWORDS
    assert "sendgrid" in FOREIGN_SENDER_KEYWORDS
    assert "smtp2go" in FOREIGN_SENDER_KEYWORDS
    assert "nl2go" in FOREIGN_SENDER_KEYWORDS
    assert "hubspot" in FOREIGN_SENDER_KEYWORDS
    assert "knowbe4" in FOREIGN_SENDER_KEYWORDS
    assert "hornetsecurity" in FOREIGN_SENDER_KEYWORDS
    assert set(FOREIGN_SENDER_KEYWORDS.keys()).isdisjoint(set(PROVIDER_KEYWORDS.keys()))


def test_skip_domains_contains_expected():
    assert "example.com" in SKIP_DOMAINS
    assert "sentry.io" in SKIP_DOMAINS
    assert "schema.org" in SKIP_DOMAINS


def test_pt_isp_asns_contains_key_providers():
    assert 1136 in PT_ISP_ASNS  # KPN
    assert 24444 in PT_ISP_ASNS  # SURFnet
    assert 50266 in PT_ISP_ASNS  # TransIP
    assert 12859 in PT_ISP_ASNS  # BIT BV
    assert 211993 in PT_ISP_ASNS  # Soverin
    assert 28685 in PT_ISP_ASNS  # Routit (StartMail)
    assert PT_ISP_ASNS[12859] == "BIT BV"
    assert PT_ISP_ASNS[211993] == "Soverin B.V."


def test_pt_isp_asns_minimum_count():
    assert len(PT_ISP_ASNS) >= 20
