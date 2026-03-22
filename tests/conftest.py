import json

import pytest


@pytest.fixture
def sample_municipality():
    return {
        "cbs": "GM0363",
        "name": "Amsterdam",
        "province": "Noord-Holland",
        "domain": "amsterdam.nl",
        "mx": ["amsterdam-nl.mail.protection.outlook.com"],
        "spf": "v=spf1 include:spf.protection.outlook.com -all",
        "provider": "microsoft",
    }


@pytest.fixture
def sovereign_municipality():
    return {
        "cbs": "GM0518",
        "name": "'s-Gravenhage",
        "province": "Zuid-Holland",
        "domain": "denhaag.nl",
        "mx": ["mx1.denhaag.nl", "mx2.denhaag.nl"],
        "spf": "v=spf1 ip4:1.2.3.4 ~all",
        "provider": "pt-isp",
    }


@pytest.fixture
def unknown_municipality():
    return {
        "cbs": "GM9999",
        "name": "Testgemeente",
        "province": "Testprovincie",
        "domain": "",
        "mx": [],
        "spf": "",
        "provider": "unknown",
    }


@pytest.fixture
def sample_data_json(tmp_path):
    data = {
        "generated": "2025-01-01T00:00:00Z",
        "total": 3,
        "counts": {"microsoft": 1, "pt-isp": 1, "unknown": 1},
        "municipalities": {
            "GM0363": {
                "cbs": "GM0363",
                "name": "Amsterdam",
                "province": "Noord-Holland",
                "domain": "amsterdam.nl",
                "mx": ["amsterdam-nl.mail.protection.outlook.com"],
                "spf": "v=spf1 include:spf.protection.outlook.com -all",
                "provider": "microsoft",
            },
            "GM0518": {
                "cbs": "GM0518",
                "name": "'s-Gravenhage",
                "province": "Zuid-Holland",
                "domain": "denhaag.nl",
                "mx": ["mx1.denhaag.nl", "mx2.denhaag.nl"],
                "spf": "v=spf1 ip4:1.2.3.4 ~all",
                "provider": "pt-isp",
            },
            "GM9999": {
                "cbs": "GM9999",
                "name": "Testgemeente",
                "province": "Testprovincie",
                "domain": "",
                "mx": [],
                "spf": "",
                "provider": "unknown",
            },
        },
    }
    path = tmp_path / "data.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path
