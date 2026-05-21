from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.routes import cert

app = FastAPI(title="SSL Certificate Checker", docs_url=None, redoc_url=None)

app.include_router(cert.router)

app.mount("/", StaticFiles(directory="app/static", html=True), name="static")
