from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .core.config import FRONTEND_ORIGIN
from .database import Base, engine

# Import models before creating database tables.
from . import models

from .routers.auth import router as auth_router
from .routers.users import router as users_router
from .routers.profile import router as profile_router
from .routers.stats import router as stats_router


app = FastAPI(
    title="Admin Management API"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type"],
)

# Retain existing database initialization.
Base.metadata.create_all(bind=engine)


# Preserve the origin check for browser write requests.
@app.middleware("http")
async def check_write_origin(
    request: Request,
    call_next
):
    if request.method in {
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }:
        origin = request.headers.get("origin")

        if origin and origin != FRONTEND_ORIGIN:
            return JSONResponse(
                {"detail": "Untrusted origin"},
                status_code=403
            )

    return await call_next(request)


# Register existing API endpoints.
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(profile_router)
app.include_router(stats_router)