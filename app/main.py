from fastapi import FastAPI

from app.routers.audit import router

app = FastAPI(title="Compliance Auditor")

app.include_router(router, prefix="/api")


@app.get("/health")
async def health():
    return {"status": "ok"}
