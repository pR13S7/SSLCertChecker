from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.parser import parse_certificate

router = APIRouter(prefix="/api")


class CertInput(BaseModel):
    pem: str


@router.post("/parse")
async def parse_cert(data: CertInput):
    try:
        result = parse_certificate(data.pem)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse certificate: {str(e)}")
