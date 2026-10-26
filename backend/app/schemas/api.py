"""Request bodies. JSON field names match the frontend types."""

from typing import Any, Literal

from pydantic import BaseModel, Field

IncidentStatusName = Literal[
    "New",
    "Investigating",
    "Contained",
    "Resolved",
    "False Positive",
]
SeverityName = Literal["critical", "high", "medium", "low", "info"]
ActionName = Literal["isolate_endpoint", "disable_account", "block_ip"]


class LoginIn(BaseModel):
    username: str
    password: str


class IncidentPatch(BaseModel):
    status: IncidentStatusName | None = None
    owner: str | None = None


class AnalystPatch(BaseModel):
    disposition: Literal["Undetermined", "True positive", "Benign", "False positive"] | None = None
    summary: str | None = None


class DetectionPatch(BaseModel):
    enabled: bool


class NoteIn(BaseModel):
    text: str = Field(min_length=1)


class PromoteIn(BaseModel):
    title: str
    severity: SeverityName
    owner: str
    events: list[dict[str, Any]]


class ActionIn(BaseModel):
    action: ActionName
    target: str = Field(min_length=1)
    confirm: bool


class HuntRunIn(BaseModel):
    id: str
    query: str
    host: str = ""
    user: str = ""
    source: str = ""
    start: str = Field(default="", alias="from")
    end: str = Field(default="", alias="to")

    model_config = {"populate_by_name": True}
