from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.api.deps import require_demo_user
from app.core.config import Settings
from app.db import get_db
from app.schemas.api import ActionIn, AnalystPatch, ChecklistPatch, IncidentPatch, NoteIn, PromoteIn
from app.services.incidents import (
    add_note,
    create_incident,
    incident_detail,
    list_incidents,
    record_dry_run,
    set_checklist_item,
    update_analyst,
    update_incident,
)

router = APIRouter()


@router.get("/incidents")
def get_incidents(
    severity: str = "",
    status: str = "",
    user: str = "",
    host: str = "",
    technique: str = "",
    from_: str = Query(default="", alias="from"),
    to: str = "",
    session: Session = Depends(get_db),
    _user: str = Depends(require_demo_user),
) -> list[dict]:
    # `from` is a Python keyword. The query parameter name is still `from`.
    return list_incidents(
        session,
        {
            "severity": severity,
            "status": status,
            "user": user,
            "host": host,
            "technique": technique,
            "from": from_,
            "to": to,
        },
    )


@router.post("/incidents")
def post_incident(
    body: PromoteIn,
    request: Request,
    session: Session = Depends(get_db),
    _user: str = Depends(require_demo_user),
) -> dict:
    settings: Settings = request.app.state.settings
    return create_incident(
        session,
        settings,
        body.title,
        body.severity,
        body.owner,
        body.events,
    )


@router.get("/incidents/{incident_id}")
def get_incident(
    incident_id: str,
    session: Session = Depends(get_db),
    _user: str = Depends(require_demo_user),
) -> dict:
    return incident_detail(session, incident_id)


@router.patch("/incidents/{incident_id}")
def patch_incident(
    incident_id: str,
    body: IncidentPatch,
    session: Session = Depends(get_db),
    _user: str = Depends(require_demo_user),
) -> dict:
    return update_incident(session, incident_id, body.status, body.owner)


@router.patch("/incidents/{incident_id}/analyst")
def patch_analyst(
    incident_id: str,
    body: AnalystPatch,
    session: Session = Depends(get_db),
    _user: str = Depends(require_demo_user),
) -> dict:
    return update_analyst(session, incident_id, body.disposition, body.summary)


@router.post("/incidents/{incident_id}/notes")
def post_note(
    incident_id: str,
    body: NoteIn,
    session: Session = Depends(get_db),
    user: str = Depends(require_demo_user),
) -> dict:
    return add_note(session, incident_id, user, body.text.strip())


@router.patch("/incidents/{incident_id}/checklist/{item_id}")
def patch_checklist(
    incident_id: str,
    item_id: str,
    body: ChecklistPatch,
    session: Session = Depends(get_db),
    _user: str = Depends(require_demo_user),
) -> dict:
    return set_checklist_item(session, incident_id, item_id, body.checked)


@router.post("/incidents/{incident_id}/actions")
def post_action(
    incident_id: str,
    body: ActionIn,
    session: Session = Depends(get_db),
    user: str = Depends(require_demo_user),
) -> dict:
    # LAB ONLY. confirm=true records a dry run. Nothing is executed.
    return record_dry_run(
        session,
        incident_id=incident_id,
        actor=user,
        action=body.action,
        target=body.target,
        confirm=body.confirm,
    )
