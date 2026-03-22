import asyncio
import json
from unittest.mock import AsyncMock, patch

from mail_sovereignty.postprocess import (
    MANUAL_OVERRIDES,
    build_urls,
    decrypt_typo3,
    extract_email_domains,
    process_unknown,
    run,
    scrape_email_domains,
)


# ── decrypt_typo3() ──────────────────────────────────────────────────


class TestDecryptTypo3:
    def test_known_encrypted(self):
        encrypted = "kygjrm8yYz,af"
        decrypted = decrypt_typo3(encrypted)
        assert decrypted == "mailto:a@b.ch"

    def test_empty_string(self):
        assert decrypt_typo3("") == ""

    def test_non_range_passthrough(self):
        assert decrypt_typo3(" ") == " "

    def test_custom_offset(self):
        result = decrypt_typo3("a", offset=1)
        assert result == "b"

    def test_wrap_around(self):
        result = decrypt_typo3("z", offset=2)
        assert result == "b"


# ── extract_email_domains() ──────────────────────────────────────────


class TestExtractEmailDomains:
    def test_plain_email(self):
        html = "Contact us at info@gemeente.nl for more info."
        assert "gemeente.nl" in extract_email_domains(html)

    def test_mailto_link(self):
        html = '<a href="mailto:contact@town.nl">Email</a>'
        assert "town.nl" in extract_email_domains(html)

    def test_typo3_obfuscated(self):
        html = """linkTo_UnCryptMailto('kygjrm8yYz,af')"""
        domains = extract_email_domains(html)
        assert "b.ch" in domains

    def test_skip_domains_filtered(self):
        html = "admin@example.com test@sentry.io"
        domains = extract_email_domains(html)
        assert "example.com" not in domains
        assert "sentry.io" not in domains

    def test_multiple_sources_combined(self):
        html = 'info@town.nl <a href="mailto:admin@city.nl">x</a>'
        domains = extract_email_domains(html)
        assert "town.nl" in domains
        assert "city.nl" in domains

    def test_no_emails(self):
        html = "<html><body>No contact here</body></html>"
        assert extract_email_domains(html) == set()


# ── build_urls() ─────────────────────────────────────────────────────


class TestBuildUrls:
    def test_bare_domain(self):
        urls = build_urls("example.nl")
        assert "https://www.example.nl/" in urls
        assert "https://example.nl/" in urls
        assert any("/contact" in u for u in urls)

    def test_www_prefix(self):
        urls = build_urls("www.example.nl")
        assert "https://www.example.nl/" in urls
        assert "https://example.nl/" in urls

    def test_https_prefix_stripped(self):
        urls = build_urls("https://example.nl")
        assert "https://www.example.nl/" in urls

    def test_includes_contact_paths(self):
        urls = build_urls("example.nl")
        assert any("/contact" in u for u in urls)
        assert any("/kontakt" in u for u in urls)


# ── MANUAL_OVERRIDES ─────────────────────────────────────────────────


class TestManualOverrides:
    def test_override_map_shape(self):
        assert isinstance(MANUAL_OVERRIDES, dict)

    def test_all_entries_have_required_keys(self):
        valid = {
            "independent",
            "microsoft",
            "pt-isp",
            "eu-isp",
            "google",
            "aws",
            "us-other",
        }
        for cbs, entry in MANUAL_OVERRIDES.items():
            # Allow domain-only, provider-only, or both depending on override intent.
            assert any(
                k in entry for k in ("domain", "provider")
            ), f"CBS {cbs} must define at least 'domain' or 'provider'"
            assert "provider" in entry, f"CBS {cbs} missing 'provider'"
            assert (
                entry["provider"] in valid
            ), f"CBS {cbs}: unexpected provider {entry['provider']}"


# ── Async functions ──────────────────────────────────────────────────


class TestScrapeEmailDomains:
    async def test_empty_domain(self):
        result = await scrape_email_domains(None, "")
        assert result == set()

    async def test_with_emails_found(self):
        class FakeResponse:
            status_code = 200
            text = "Contact us at info@gemeente.nl"

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        result = await scrape_email_domains(client, "gemeente.nl")
        assert "gemeente.nl" in result


class TestProcessUnknown:
    async def test_no_domain_returns_unchanged(self):
        m = {"cbs": "GM0999", "name": "Test", "domain": "", "provider": "unknown"}
        sem = asyncio.Semaphore(10)
        client = AsyncMock()

        result = await process_unknown(client, sem, m)
        assert result["provider"] == "unknown"

    async def test_resolves_via_email_scraping(self):
        m = {
            "cbs": "GM0999",
            "name": "Test",
            "domain": "test.nl",
            "provider": "unknown",
        }
        sem = asyncio.Semaphore(10)

        class FakeResponse:
            status_code = 200
            text = "Contact us at info@test.nl"

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        with (
            patch(
                "mail_sovereignty.postprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["mail.test.nl"],
            ),
            patch(
                "mail_sovereignty.postprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="",
            ),
            patch(
                "mail_sovereignty.postprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await process_unknown(client, sem, m)

        assert result["provider"] == "independent"

    async def test_no_email_domains_found(self):
        m = {
            "cbs": "GM0999",
            "name": "Test",
            "domain": "test.nl",
            "provider": "unknown",
        }
        sem = asyncio.Semaphore(10)

        class FakeResponse:
            status_code = 200
            text = "<html>No emails here</html>"

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        result = await process_unknown(client, sem, m)
        assert result["provider"] == "unknown"


class TestScrapeEmailDomainsNoEmails:
    async def test_non_200_skipped(self):
        class FakeResponse:
            status_code = 404
            text = ""

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        result = await scrape_email_domains(client, "test.nl")
        assert result == set()

    async def test_exception_handled(self):
        client = AsyncMock()
        client.get = AsyncMock(side_effect=Exception("connection error"))

        result = await scrape_email_domains(client, "test.nl")
        assert result == set()


class TestDnsRetryStep:
    async def test_recovers_unknown_with_domain(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"unknown": 1},
            "municipalities": {
                "GM1234": {
                    "cbs": "GM1234",
                    "name": "Testgemeente",
                    "province": "Noord-Holland",
                    "domain": "testgemeente.nl",
                    "mx": [],
                    "spf": "",
                    "provider": "unknown",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with (
            patch(
                "mail_sovereignty.postprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["testgemeente-nl.mail.protection.outlook.com"],
            ),
            patch(
                "mail_sovereignty.postprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.postprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            await run(path)

        result = json.loads(path.read_text())
        assert result["municipalities"]["GM1234"]["provider"] == "microsoft"

    async def test_skips_unknown_without_domain(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"unknown": 1},
            "municipalities": {
                "GM9999": {
                    "cbs": "GM9999",
                    "name": "NoDomain",
                    "province": "Testprovincie",
                    "domain": "",
                    "mx": [],
                    "spf": "",
                    "provider": "unknown",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        await run(path)

        result = json.loads(path.read_text())
        assert result["municipalities"]["GM9999"]["provider"] == "unknown"


class TestSmtpBannerStep:
    async def test_reclassifies_independent_via_smtp(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"independent": 1},
            "municipalities": {
                "GM1000": {
                    "cbs": "GM1000",
                    "name": "SmtpTown",
                    "province": "Testprovincie",
                    "domain": "smtptown.nl",
                    "mx": ["mail.smtptown.nl"],
                    "spf": "",
                    "provider": "independent",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with patch(
            "mail_sovereignty.postprocess.fetch_smtp_banner",
            new_callable=AsyncMock,
            return_value={
                "banner": "220 mail.protection.outlook.com Microsoft ESMTP MAIL Service ready",
                "ehlo": "250 ready",
            },
        ):
            await run(path)

        result = json.loads(path.read_text())
        assert result["municipalities"]["GM1000"]["provider"] == "microsoft"
        assert "smtp_banner" in result["municipalities"]["GM1000"]

    async def test_leaves_independent_when_banner_is_postfix(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"independent": 1},
            "municipalities": {
                "GM1001": {
                    "cbs": "GM1001",
                    "name": "PostfixTown",
                    "province": "Testprovincie",
                    "domain": "postfixtown.nl",
                    "mx": ["mail.postfixtown.nl"],
                    "spf": "",
                    "provider": "independent",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with patch(
            "mail_sovereignty.postprocess.fetch_smtp_banner",
            new_callable=AsyncMock,
            return_value={
                "banner": "220 mail.postfixtown.nl ESMTP Postfix",
                "ehlo": "250 mail.postfixtown.nl",
            },
        ):
            await run(path)

        result = json.loads(path.read_text())
        assert result["municipalities"]["GM1001"]["provider"] == "independent"
        assert "smtp_banner" in result["municipalities"]["GM1001"]

    async def test_skips_already_classified(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"microsoft": 1},
            "municipalities": {
                "GM1002": {
                    "cbs": "GM1002",
                    "name": "AlreadyKnown",
                    "province": "Testprovincie",
                    "domain": "known.nl",
                    "mx": ["mail.protection.outlook.com"],
                    "spf": "v=spf1 include:spf.protection.outlook.com -all",
                    "provider": "microsoft",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with patch(
            "mail_sovereignty.postprocess.fetch_smtp_banner",
            new_callable=AsyncMock,
        ) as mock_fetch:
            await run(path)
            mock_fetch.assert_not_called()

    async def test_deduplicates_mx_hosts(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 2,
            "counts": {"independent": 2},
            "municipalities": {
                "GM2000": {
                    "cbs": "GM2000",
                    "name": "Town1",
                    "province": "Testprovincie",
                    "domain": "town1.nl",
                    "mx": ["shared-mx.example.nl"],
                    "spf": "",
                    "provider": "independent",
                },
                "GM2001": {
                    "cbs": "GM2001",
                    "name": "Town2",
                    "province": "Testprovincie",
                    "domain": "town2.nl",
                    "mx": ["shared-mx.example.nl"],
                    "spf": "",
                    "provider": "independent",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with patch(
            "mail_sovereignty.postprocess.fetch_smtp_banner",
            new_callable=AsyncMock,
            return_value={
                "banner": "220 mail.protection.outlook.com Microsoft ESMTP MAIL Service",
                "ehlo": "250 ready",
            },
        ) as mock_fetch:
            await run(path)
            assert mock_fetch.call_count == 1

        result = json.loads(path.read_text())
        assert result["municipalities"]["GM2000"]["provider"] == "microsoft"
        assert result["municipalities"]["GM2001"]["provider"] == "microsoft"

    async def test_empty_banner_no_change(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"independent": 1},
            "municipalities": {
                "GM3000": {
                    "cbs": "GM3000",
                    "name": "NoConnect",
                    "province": "Testprovincie",
                    "domain": "noconnect.nl",
                    "mx": ["mail.noconnect.nl"],
                    "spf": "",
                    "provider": "independent",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with patch(
            "mail_sovereignty.postprocess.fetch_smtp_banner",
            new_callable=AsyncMock,
            return_value={"banner": "", "ehlo": ""},
        ):
            await run(path)

        result = json.loads(path.read_text())
        assert result["municipalities"]["GM3000"]["provider"] == "independent"
        assert "smtp_banner" not in result["municipalities"]["GM3000"]


class TestPostprocessRun:
    async def test_no_manual_overrides_applied(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"unknown": 1},
            "municipalities": {
                "GM0363": {
                    "cbs": "GM0363",
                    "name": "Amsterdam",
                    "province": "Noord-Holland",
                    "domain": "",
                    "mx": [],
                    "spf": "",
                    "provider": "unknown",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        await run(path)

        result = json.loads(path.read_text())
        # No manual overrides for NL; municipality stays unknown
        assert result["municipalities"]["GM0363"]["provider"] == "unknown"
