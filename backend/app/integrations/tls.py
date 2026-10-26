"""TLS settings for the Wazuh manager API and the indexer."""

import logging

from app.core.config import REPO_ROOT, Settings

logger = logging.getLogger("sentinelforge.wazuh")


def tls_verify(settings: Settings) -> bool | str:
    """Return the httpx `verify` value.

    A CA bundle path is preferred. `WAZUH_TLS_INSECURE=true` is LAB ONLY and is
    logged on every client construction, which is startup in live mode.
    """

    if settings.wazuh_tls_insecure:
        logger.warning("LAB ONLY: TLS verification disabled")
        return False
    bundle = settings.wazuh_ca_bundle.strip()
    if not bundle:
        return True
    path = REPO_ROOT / bundle if not bundle.startswith("/") else bundle
    return str(path)
