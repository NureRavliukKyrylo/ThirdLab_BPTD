from fastapi import APIRouter, Request, UploadFile, File, Form
from fastapi.responses import HTMLResponse
from pathlib import Path
import tempfile

from hash import secure_hash

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return request.app.state.templates.TemplateResponse(
        "index.html",
        {"request": request}
    )


@router.post("/hash", response_class=HTMLResponse)
async def compute_and_verify_hash(
    request: Request,
    file: UploadFile = File(...),
    bits: int = Form(...),
    expected_digest: str | None = Form(None),
):
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    digest = secure_hash(tmp_path, bit_length=bits)

    Path(tmp_path).unlink(missing_ok=True)

    verification_result = None
    valid_expected = None

    if expected_digest:
        expected_digest = expected_digest.strip()
        valid_expected = (
            len(expected_digest) == bits
            and all(ch in "01" for ch in expected_digest)
        )
        if valid_expected:
            verification_result = (expected_digest == digest)
        else:
            verification_result = False

    return request.app.state.templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "filename": file.filename,
            "bits": bits,
            "digest": digest,
            "expected_digest": expected_digest,
            "valid_expected": valid_expected,
            "verification_result": verification_result,
        }
    )
