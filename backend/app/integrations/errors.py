"""Typed Wazuh failures. Messages are safe to return to the console."""


class WazuhError(Exception):
    """Base error. The text is shown to the analyst and must not include secrets."""


class WazuhAuthError(WazuhError):
    """Login was rejected, or a refreshed token was still refused."""


class WazuhUnavailable(WazuhError):
    """The manager API or the indexer could not be reached."""


class WazuhResponseError(WazuhError):
    """The service answered with a body or status this client does not accept."""


class HuntQueryRejected(WazuhError):
    """The hunt query is outside the allow-list or the time window."""


class ArchivesNotEnabled(WazuhResponseError):
    def __init__(self) -> None:
        super().__init__(
            "Archives not enabled on WAZUH01, see docs/runbooks/wazuh-archives.md"
        )
