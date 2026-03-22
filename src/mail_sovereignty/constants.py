import re

MICROSOFT_KEYWORDS = [
    "mail.protection.outlook.com",
    "outlook.com",
    "outook.com",
    "microsoft",
    "office365",
    "onmicrosoft",
    "spf.protection.outlook.com",
    "sharepointonline",
]
GOOGLE_KEYWORDS = [
    "google",
    "googlemail",
    "gmail.com",
    "_spf.google.com",
    "aspmx.l.google.com",
]
AWS_KEYWORDS = ["amazonaws", "amazonses", "awsdns"]
US_OTHER_KEYWORDS = [
    "mpssec.net",
    "anubisnetworks.com",
    "fortimailcloud.com",
    "fortimail.com",
]

# SPF profiles that frequently delegate sending infrastructure to AWS.
AWS_SPF_HINT_KEYWORDS = ["webapps.net"]

PROVIDER_KEYWORDS = {
    "microsoft": MICROSOFT_KEYWORDS,
    "google": GOOGLE_KEYWORDS,
    "aws": AWS_KEYWORDS,
    "us-other": US_OTHER_KEYWORDS,
}

# ASNs whose IP blocks in a resolved SPF record confirm the *mailbox* provider.
# Only include ASNs that are specific to mailbox hosting services:
#   - Microsoft Exchange Online (spf.protection.outlook.com IP ranges)
#   - Google Workspace (_spf.google.com IP ranges)
# AWS is intentionally excluded: AS16509/14618 appear in SPF for Amazon SES
# (transactional/bulk sending) even when the actual mailbox is elsewhere.
MAILBOX_ASNS: dict[int, str] = {
    8075: "microsoft",  # Microsoft Corporation (Exchange Online)
    8070: "microsoft",  # Microsoft Corp (legacy)
    3598: "microsoft",  # Microsoft Corp (legacy)
    15169: "google",  # Google LLC (Google Workspace)
}

FOREIGN_SENDER_KEYWORDS = {
    "mailchimp": ["mandrillapp.com", "mandrill", "mcsv.net"],
    "sendgrid": ["sendgrid"],
    "mailjet": ["mailjet"],
    "mailgun": ["mailgun"],
    "brevo": ["sendinblue", "brevo"],
    "mailchannels": ["mailchannels"],
    "smtp2go": ["smtp2go"],
    "nl2go": ["nl2go"],
    "hubspot": ["hubspotemail"],
    "knowbe4": ["knowbe4"],
    "hornetsecurity": ["hornetsecurity", "hornetdmarc"],
    # Zivver: secure email vendor, acquired by Kiteworks (California, US) June 2025
    # Subject to US CLOUD Act despite EU data residency claims
    "zivver": ["zivver"],
}

SPARQL_URL = "https://query.wikidata.org/sparql"
SPARQL_QUERY = """
SELECT ?item ?itemLabel ?cbs ?website ?provinceLabel WHERE {
  ?item p:P31 ?activeStmt .            # require an active P31 statement
    ?activeStmt ps:P31 wd:Q2039348 .    # instance of: municipality
  FILTER NOT EXISTS {                  # no end time on this statement (still active)
    ?activeStmt pq:P582 ?endTime .
  }
  ?item wdt:P382 ?cbs .                # CBS municipality code
  FILTER NOT EXISTS {                  # exclude dissolved municipalities
    ?item wdt:P576 ?dissolved .
    FILTER(?dissolved <= NOW())
  }
  FILTER NOT EXISTS {                  # exclude municipalities replaced by a successor
    ?item wdt:P1366 ?successor .
  }
  OPTIONAL { ?item wdt:P856 ?website . }
  OPTIONAL { ?item wdt:P131 ?province .
             ?province wdt:P31 wd:Q134390 . }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "nl,en" . }
}
ORDER BY xsd:integer(?cbs)
"""

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
TYPO3_RE = re.compile(r"linkTo_UnCryptMailto\(['\"]([^'\"]+)['\"]")
SKIP_DOMAINS = {
    "example.com",
    "example.nl",
    "sentry.io",
    "w3.org",
    "gstatic.com",
    "googleapis.com",
    "schema.org",
}

SUBPAGES = [
    "/kontakt",
    "/contact",
    "/contact/",
    "/bestuur",
    "/bestuur/",
    "/gemeenteraad",
    "/gemeenteraad/",
    "/organisatie",
    "/organisatie/",
]

GATEWAY_KEYWORDS = {
    "seppmail": ["seppmail.cloud", "seppmail.com"],
    "barracuda": ["barracudanetworks.com", "barracuda.com"],
    "trendmicro": ["tmes.trendmicro.eu", "tmes.trendmicro.com"],
    "hornetsecurity": ["hornetsecurity.com"],
    "abxsec": ["abxsec.com"],
    "proofpoint": ["ppe-hosted.com"],
    "sophos": ["hydra.sophos.com"],
    "spamvor": ["spamvor.com"],
}

PT_ISP_ASNS: dict[int, str] = {
    # Telecom / access ISPs
    1136: "KPN B.V.",
    3265: "XS4ALL Internet B.V.",
    24587: "Vodafone Libertel N.V.",
    33915: "Vodafone Netherlands",
    # Hosters / datacenters
    8283: "Leaseweb Netherlands B.V.",
    12859: "BIT BV",
    15703: "True B.V.",
    20847: "Previder B.V.",
    20940: "Akamai Technologies",
    21221: "InfoPact Internet Services",
    25596: "Centric B.V.",
    28685: "Routit B.V.",  # hosts StartMail
    28878: "Signet B.V.",
    29311: "Solvinity N.V.",
    31673: "Uniserver Internet B.V.",
    34968: "iunxi B.V.",
    39647: "Previder B.V.",
    42836: "Schuberg Philis B.V.",
    50266: "TransIP B.V.",
    51088: "A2B IP B.V.",
    # Research / education
    24444: "SURFnet B.V.",
    # Sovereign / privacy-first Portuguese/local-first email
    206238: "Freedom Internet B.V.",
    211993: "Soverin B.V.",
    # Portuguese/shared public services and regional IT cooperatives
    # (only where the MX host itself belongs to the provider, not just network transit)
    38915: "Solido Gemeenschappelijk Regeling",  # fm01.as38915.net — Limburg municipalities
    34373: "XXLnet B.V.",
    35332: "DataWeb B.V.",
    199752: "Go-Trex Internet Solution Partner",
    42585: "Metaregistrar B.V.",  # yourdomainprovider.net
    39591: "Previder B.V.",  # GLOBAL-E brand
    # Legacy / security
    15435: "Ecatel Ltd.",
}

# MX host keywords that identify Portuguese ISP/shared municipal email relays.
PT_ISP_KEYWORDS = [
    "ptempresas.pt",
    "ptasp.com",
    "mail.ptempresas.pt",
    "mxc.ptempresas.pt",
    "mxp.ptempresas.pt",
]

# MX host keywords for European (non-Portuguese) ISP/hoster relays.
EU_ISP_KEYWORDS = [
    "ovh.net",
    "ovh.com",
    "ohv.com",
]

CONCURRENCY = 20
CONCURRENCY_POSTPROCESS = 10
CONCURRENCY_SMTP = 5

SMTP_BANNER_KEYWORDS = {
    "microsoft": [
        "microsoft esmtp mail service",
        "outlook.com",
        "protection.outlook.com",
    ],
    "google": [
        "mx.google.com",
        "google esmtp",
    ],
    "aws": [
        "amazonaws",
        "amazonses",
    ],
    "us-other": [
        "mpssec.net",
        "anubisnetworks.com",
        "fortimailcloud.com",
        "fortimail.com",
    ],
}
