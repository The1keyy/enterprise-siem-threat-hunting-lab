from fastapi import APIRouter, Depends

from app.api.catalog import router as catalog_router
from app.api.deps import require_demo_user
from app.api.hunts import router as hunts_router
from app.api.incidents import router as incidents_router

router = APIRouter(prefix="/api", dependencies=[Depends(require_demo_user)])
router.include_router(catalog_router)
router.include_router(incidents_router)
router.include_router(hunts_router)
