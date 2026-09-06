import os
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import pytest

from src.data.singapore_guidance import OFFICIAL_HANDOFFS
from src.tools.bank_tools import BANK_HANDOFFS


ALLOWED_DOMAINS = {
    "www.scamshield.gov.sg", "guide.scamshield.gov.sg", "www.police.gov.sg",
    "portal.singpass.gov.sg", "www.dbs.com.sg", "www.ocbc.com", "www.uob.com.sg",
}


def official_urls() -> list[str]:
    return [*OFFICIAL_HANDOFFS.values(), *(entry["url"] for entry in BANK_HANDOFFS.values())]


def test_official_links_are_https_and_allowlisted() -> None:
    for url in official_urls():
        parsed = urlparse(url)
        assert parsed.scheme == "https"
        assert parsed.hostname in ALLOWED_DOMAINS


@pytest.mark.skipif(os.getenv("FIRST30_CHECK_EXTERNAL_LINKS") != "1", reason="opt-in network check")
@pytest.mark.parametrize("url", official_urls())
def test_official_links_resolve_without_not_found(url: str) -> None:
    request = Request(url, headers={"User-Agent": "First30 link verifier/1.0"})
    with urlopen(request, timeout=15) as response:
        assert response.status not in {404, 410}
