import json
from unittest.mock import AsyncMock, patch

import httpx
import respx

from mail_sovereignty.preprocess import (
    fetch_municipalities,
    guess_domains,
    run,
    scan_municipality,
    url_to_domain,
)


# ── url_to_domain() ─────────────────────────────────────────────────


class TestUrlToDomain:
    def test_full_url_with_path(self):
        assert url_to_domain("https://www.amsterdam.nl/some/path") == "amsterdam.nl"

    def test_no_scheme(self):
        assert url_to_domain("amsterdam.nl") == "amsterdam.nl"

    def test_strips_www(self):
        assert url_to_domain("https://www.example.nl") == "example.nl"

    def test_empty_string(self):
        assert url_to_domain("") is None

    def test_none(self):
        assert url_to_domain(None) is None

    def test_bare_domain(self):
        assert url_to_domain("example.nl") == "example.nl"

    def test_http_scheme(self):
        assert url_to_domain("http://example.nl/page") == "example.nl"


# ── guess_domains() ─────────────────────────────────────────────────


class TestGuessDomains:
    def test_simple_name(self):
        domains = guess_domains("Amsterdam")
        assert "amsterdam.pt" in domains
        assert "cm-amsterdam.pt" in domains

    def test_parenthetical_stripped(self):
        domains = guess_domains("Bergen (NH)")
        assert any("bergen" in d for d in domains)
        assert not any("NH" in d for d in domains)

    def test_apostrophe_removed(self):
        domains = guess_domains("'s-Hertogenbosch")
        assert any("s-hertogenbosch" in d for d in domains)

    def test_no_ch_domains(self):
        domains = guess_domains("Amsterdam")
        assert not any(d.endswith(".ch") for d in domains)


# ── fetch_municipalities() ─────────────────────────────────────────────────


class TestFetchMunicipalities:
    async def test_success(self):
        result = await fetch_municipalities()
        assert len(result) >= 300
        assert "0101" in result
        assert result["0101"]["name"] == "Águeda"
        assert result["0101"]["website"].startswith("https://")

    async def test_unique_ids(self):
        result = await fetch_municipalities()
        assert len(result) == len(set(result.keys()))

    async def test_con_code_format(self):
        result = await fetch_municipalities()
        assert any(k.isdigit() and len(k) == 4 for k in result)


# ── scan_municipality() ──────────────────────────────────────────────


class TestScanMunicipality:
    async def test_website_domain_mx_found(self):
        m = {
            "cbs": "GM0363",
            "name": "Amsterdam",
            "province": "Noord-Holland",
            "website": "https://www.amsterdam.nl",
        }
        sem = __import__("asyncio").Semaphore(10)

        with (
            patch(
                "mail_sovereignty.preprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["mail.protection.outlook.com"],
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "microsoft"
        assert result["domain"] == "amsterdam.nl"

    async def test_no_website_guesses_domain(self):
        m = {
            "cbs": "GM0363",
            "name": "Amsterdam",
            "province": "Noord-Holland",
            "website": "",
        }
        sem = __import__("asyncio").Semaphore(10)

        async def fake_lookup_mx(domain):
            if domain == "amsterdam.pt":
                return ["mail.amsterdam.pt"]
            return []

        with (
            patch("mail_sovereignty.preprocess.lookup_mx", side_effect=fake_lookup_mx),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="",
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="",
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_mx_cnames",
                new_callable=AsyncMock,
                return_value={},
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_mx_asns",
                new_callable=AsyncMock,
                return_value=set(),
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "independent"
        assert result["domain"] == "amsterdam.pt"

    async def test_no_mx_unknown(self):
        m = {"cbs": "GM0999", "name": "TestGemeente", "province": "Test", "website": ""}
        sem = __import__("asyncio").Semaphore(10)

        with (
            patch(
                "mail_sovereignty.preprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="",
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "unknown"

    async def test_gateway_detected_and_stored(self):
        m = {
            "cbs": "GM0228",
            "name": "Testgemeente",
            "province": "Gelderland",
            "website": "https://www.testgemeente.nl",
        }
        sem = __import__("asyncio").Semaphore(10)

        with (
            patch(
                "mail_sovereignty.preprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["mx01.hornetsecurity.com"],
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "microsoft"
        assert result["gateway"] == "hornetsecurity"

    async def test_spf_resolved_stored_when_different(self):
        m = {
            "cbs": "GM0100",
            "name": "Test",
            "province": "Test",
            "website": "https://www.test.nl",
        }
        sem = __import__("asyncio").Semaphore(10)

        raw_spf = "v=spf1 include:custom.nl -all"
        resolved_spf = "v=spf1 include:custom.nl -all v=spf1 include:spf.protection.outlook.com -all"

        with (
            patch(
                "mail_sovereignty.preprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["mx01.hornetsecurity.com"],
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value=raw_spf,
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value=resolved_spf,
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "microsoft"
        assert result["gateway"] == "hornetsecurity"
        assert result["spf_resolved"] == resolved_spf

    async def test_autodiscover_stored_when_found(self):
        m = {
            "cbs": "GM0500",
            "name": "Teststad",
            "province": "Overijssel",
            "website": "https://www.teststad.nl",
        }
        sem = __import__("asyncio").Semaphore(10)

        with (
            patch(
                "mail_sovereignty.preprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["mx01.hornetsecurity.com"],
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="v=spf1 ip4:1.2.3.4 -all",
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="v=spf1 ip4:1.2.3.4 -all",
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={"autodiscover_cname": "autodiscover.outlook.com"},
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "microsoft"
        assert result["gateway"] == "hornetsecurity"
        assert result["autodiscover"] == {
            "autodiscover_cname": "autodiscover.outlook.com"
        }


# ── run() ────────────────────────────────────────────────────────────


class TestPreprocessRun:
    async def test_writes_output(self, tmp_path):
        with (
            patch(
                "mail_sovereignty.preprocess.fetch_municipalities",
                new_callable=AsyncMock,
                return_value={
                    "0101": {
                        "cbs": "0101",
                        "con_code": "0101",
                        "municipio": "Águeda",
                        "name": "Águeda",
                        "province": "Aveiro",
                        "website": "https://cm-agueda.pt",
                    }
                },
            ),
            patch(
                "mail_sovereignty.preprocess.scan_municipality",
                new_callable=AsyncMock,
                return_value={
                    "cbs": "0101",
                    "con_code": "0101",
                    "municipio": "Águeda",
                    "name": "Águeda",
                    "province": "Aveiro",
                    "domain": "cm-agueda.pt",
                    "mx": ["mail.cm-agueda.pt"],
                    "spf": "",
                    "provider": "independent",
                },
            ),
        ):
            output = tmp_path / "data.json"
            await run(output)

        assert output.exists()
        data = json.loads(output.read_text())
        assert data["total"] == 1
        assert "0101" in data["municipalities"]
