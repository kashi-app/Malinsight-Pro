import re

from strings import extract_strings


# ------------------------------------------------------------
# Regular Expressions
# ------------------------------------------------------------

URL_REGEX = re.compile(
    r'https?://[^\s\'"<>]+',
    re.IGNORECASE
)

DOMAIN_REGEX = re.compile(
    r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
)

IP_REGEX = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)

EMAIL_REGEX = re.compile(
    r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
)

REGISTRY_REGEX = re.compile(
    r'HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\[^\s]+',
    re.IGNORECASE
)


# ------------------------------------------------------------
# IOC Extraction
# ------------------------------------------------------------

def extract_iocs(file_path):

    strings_data = extract_strings(file_path)

    strings = strings_data["strings"]

    urls = set()
    domains = set()
    ips = set()
    emails = set()
    registry = set()

    for s in strings:

        urls.update(URL_REGEX.findall(s))
        domains.update(DOMAIN_REGEX.findall(s))
        ips.update(IP_REGEX.findall(s))
        emails.update(EMAIL_REGEX.findall(s))
        registry.update(REGISTRY_REGEX.findall(s))

    return {

        "urls": sorted(urls),

        "domains": sorted(domains),

        "ips": sorted(ips),

        "emails": sorted(emails),

        "registry": sorted(registry),

        "summary": {

            "URLs": len(urls),

            "Domains": len(domains),

            "IPs": len(ips),

            "Emails": len(emails),

            "Registry Keys": len(registry)

        }

    }