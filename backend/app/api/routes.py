
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel, Field

from backend.app.services.ollama_service import (
    analyze_evidence,
    analyze_forensic_artifact,
    check_ollama_health,
)
from backend.app.services.investigation_service import (
    run_investigation,
)
from backend.app.services.tsk_service import (
    inspect_partitions,
    inspect_filesystem,
    list_deleted_entries,
    list_filesystem_entries,
    extract_file_content,
)

router = APIRouter()

# Forensic image upload settings
UPLOAD_DIR = Path(__file__).resolve().parents[3] / "data" / "uploads"
MAX_UPLOAD_BYTES = 1024 * 1024 * 1024  # 1024 MB

ALLOWED_IMAGE_EXTENSIONS = {
    ".dd",
    ".img",
    ".raw",
    ".e01",
}


class AIAnalysisRequest(BaseModel):
    evidence_text: str = Field(
        ...,
        min_length=1,
        max_length=20000,
        description="Extracted forensic evidence for AI analysis",
    )


class ForensicImageRequest(BaseModel):
    image_path: str = Field(
        ...,
        min_length=1,
        max_length=1000,
        description=(
            "Path to an existing forensic image "
            "on the backend computer"
        ),
    )


class FilesystemInspectionRequest(ForensicImageRequest):
    partition_offset: int | None = Field(
        default=None,
        ge=0,
        description="Partition start offset in sectors, if applicable",
    )


class DeletedEntriesRequest(FilesystemInspectionRequest):
    pass


class FileExtractionRequest(FilesystemInspectionRequest):
    metadata_address: int = Field(
        ...,
        ge=0,
        description="TSK metadata address of the file to extract",
    )


@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "CyberGuard API",
    }


@router.get("/health/dependencies")
def dependency_health():
    return {
        "api": "healthy",
        "ollama": check_ollama_health(),
    }


@router.get("/health/ollama")
def ollama_health():
    status = check_ollama_health()

    if (
        not status.get("available")
        or not status.get("model_available")
    ):
        raise HTTPException(status_code=503, detail=status)

    return status


@router.post("/ai/analyze")
def ai_analyze(request: AIAnalysisRequest):
    try:
        result = analyze_evidence(request.evidence_text)

        return {
            "status": "success",
            "result": result,
            "warning": (
                "AI analysis is interpretive assistance. "
                "Verify conclusions against original evidence."
            ),
        }

    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error

    except RuntimeError as error:
        raise HTTPException(
            status_code=503,
            detail=str(error),
        ) from error


@router.post("/investigations")
def create_investigation(request: dict):
    try:
        return run_investigation(request)

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error


@router.post("/forensics/upload")
async def upload_forensic_image(file: UploadFile = File(...)):
    """Save an uploaded forensic image for subsequent investigation."""

    original_name = Path(file.filename or "").name
    extension = Path(original_name).suffix.lower()

    if extension not in ALLOWED_IMAGE_EXTENSIONS:
        await file.close()
        raise HTTPException(
            status_code=415,
            detail=(
                "Unsupported image format. "
                "Allowed extensions: .dd, .img, .raw, .e01"
            ),
        )

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    saved_path = UPLOAD_DIR / f"{uuid4().hex}{extension}"
    total_bytes = 0

    try:
        with saved_path.open("wb") as destination:
            while True:
                chunk = await file.read(1024 * 1024)

                if not chunk:
                    break

                total_bytes += len(chunk)

                if total_bytes > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail="Image exceeds the 500 MB upload limit.",
                    )

                destination.write(chunk)

        if total_bytes == 0:
            raise HTTPException(
                status_code=400,
                detail="The uploaded file is empty.",
            )

        return {
            "status": "success",
            "filename": original_name,
            "image_path": str(saved_path.resolve()),
            "size_bytes": total_bytes,
            "message": (
                "Image uploaded successfully. Use image_path "
                "in an investigation request to analyze the image."
            ),
        }

    except Exception:
        if saved_path.exists():
            saved_path.unlink()
        raise

    finally:
        await file.close()


@router.post("/forensics/partitions")
def get_forensic_partitions(request: ForensicImageRequest):
    try:
        image_path = Path(request.image_path).expanduser()

        if not image_path.is_absolute():
            raise HTTPException(
                status_code=400,
                detail="Please provide an absolute local image path.",
            )

        result = inspect_partitions(image_path)

        if not result.get("success"):
            raise HTTPException(
                status_code=422,
                detail={
                    "message": (
                        "The Sleuth Kit could not inspect this image."
                    ),
                    "tool_result": result,
                },
            )

        return {
            "status": "success",
            "image": result["image_name"],
            "tool": result["tool"],
            "partition_output": result["stdout"],
            "warning": (
                "Partition output is raw forensic-tool output. "
                "Review it before drawing conclusions."
            ),
        }

    except HTTPException:
        raise

    except FileNotFoundError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        ) from error

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    except TimeoutError as error:
        raise HTTPException(
            status_code=504,
            detail=str(error),
        ) from error


@router.post("/forensics/filesystem")
def get_forensic_filesystem(
    request: FilesystemInspectionRequest,
):
    try:
        result = inspect_filesystem(
            request.image_path,
            request.partition_offset,
        )

        if not result.get("success"):
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "Filesystem inspection failed.",
                    "tool_result": result,
                },
            )

        return {
            "status": "success",
            "image": result["image_name"],
            "partition_offset_sectors": (
                result["partition_offset_sectors"]
            ),
            "filesystem_output": result["stdout"],
            "warning": (
                "Verify findings against the original forensic image."
            ),
        }

    except HTTPException:
        raise

    except FileNotFoundError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        ) from error

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    except TimeoutError as error:
        raise HTTPException(
            status_code=504,
            detail=str(error),
        ) from error


@router.post("/forensics/deleted-entries")
def get_deleted_entries(request: DeletedEntriesRequest):
    try:
        result = list_deleted_entries(
            request.image_path,
            request.partition_offset,
        )

        if not result.get("success"):
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "Deleted-entry listing failed.",
                    "tool_result": result,
                },
            )

        return {
            "status": "success",
            "image": result["image_name"],
            "partition_offset_sectors": (
                result["partition_offset_sectors"]
            ),
            "entries": result["stdout"],
            "warning": (
                "TSK-reported deleted entries require forensic "
                "verification. A listing does not prove that file "
                "contents are recoverable."
            ),
        }

    except HTTPException:
        raise

    except FileNotFoundError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        ) from error

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    except TimeoutError as error:
        raise HTTPException(
            status_code=504,
            detail=str(error),
        ) from error


@router.post("/forensics/files")
def get_forensic_files(request: FilesystemInspectionRequest):
    try:
        result = list_filesystem_entries(
            request.image_path,
            request.partition_offset,
        )

        if not result.get("success"):
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "Filesystem file listing failed.",
                    "tool_result": result,
                },
            )

        return {
            "status": "success",
            "image": result["image_name"],
            "partition_offset_sectors": (
                result["partition_offset_sectors"]
            ),
            "entries": result["stdout"],
            "output_truncated": result["output_truncated"],
            "warning": (
                "Entries are reported by The Sleuth Kit. "
                "A listing alone does not establish file integrity "
                "or recoverability."
            ),
        }

    except HTTPException:
        raise

    except FileNotFoundError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        ) from error

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    except TimeoutError as error:
        raise HTTPException(
            status_code=504,
            detail=str(error),
        ) from error


@router.post("/forensics/extract")
def extract_forensic_file(request: FileExtractionRequest):
    try:
        result = extract_file_content(
            image_path=request.image_path,
            metadata_address=request.metadata_address,
            partition_offset=request.partition_offset,
        )

        if not result.get("success"):
            tool_result = {
                key: value
                for key, value in result.items()
                if key != "content"
            }

            raise HTTPException(
                status_code=422,
                detail={
                    "message": "File extraction failed.",
                    "tool_result": tool_result,
                },
            )

        content = result["content"]

        try:
            text_content = content.decode("utf-8")
            content_encoding = "utf-8"
        except UnicodeDecodeError:
            text_content = None
            content_encoding = "binary-or-non-UTF-8"

        return {
            "status": "success",
            "image": result["image_name"],
            "metadata_address": result["metadata_address"],
            "partition_offset_sectors": (
                result["partition_offset_sectors"]
            ),
            "size_bytes": result["size_bytes"],
            "content_encoding": content_encoding,
            "text_content": text_content,
            "warning": (
                "Extracted content is untrusted forensic evidence. "
                "Preserve the original image and verify findings."
            ),
        }

    except HTTPException:
        raise

    except FileNotFoundError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        ) from error

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    except TimeoutError as error:
        raise HTTPException(
            status_code=504,
            detail=str(error),
        ) from error


@router.post("/forensics/analyze-file")
def analyze_extracted_file(request: FileExtractionRequest):
    try:
        extracted = extract_file_content(
            image_path=request.image_path,
            metadata_address=request.metadata_address,
            partition_offset=request.partition_offset,
        )

        if not extracted.get("success"):
            tool_result = {
                key: value
                for key, value in extracted.items()
                if key != "content"
            }

            raise HTTPException(
                status_code=422,
                detail={
                    "message": "File extraction failed.",
                    "tool_result": tool_result,
                },
            )

        content = extracted["content"]

        try:
            evidence_text = content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise HTTPException(
                status_code=415,
                detail=(
                    "The extracted file is not valid UTF-8 text. "
                    "Use a suitable format-specific parser instead."
                ),
            ) from error

        result = analyze_forensic_artifact(
            evidence_text=evidence_text,
            image_name=extracted["image_name"],
            metadata_address=extracted["metadata_address"],
            partition_offset=extracted["partition_offset_sectors"],
        )

        result["extraction"] = {
            "size_bytes": extracted["size_bytes"],
            "content_encoding": "utf-8",
        }

        return result

    except HTTPException:
        raise

    except FileNotFoundError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        ) from error

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    except TimeoutError as error:
        raise HTTPException(
            status_code=504,
            detail=str(error),
        ) from error

    except RuntimeError as error:
        raise HTTPException(
            status_code=503,
            detail=str(error),
        ) from error
