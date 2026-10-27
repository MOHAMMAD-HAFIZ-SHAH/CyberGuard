
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from backend.app.agents.case_manager import create_case
from backend.app.agents.planner import create_investigation_plan
from backend.app.agents.log_agent import investigate_logs
from backend.app.agents.hypothesis_agent import generate_hypotheses
from backend.app.agents.verification_agent import verify_hypotheses
from backend.app.agents.contradiction_agent import find_contradictions
from backend.app.agents.timeline_agent import create_timeline
from backend.app.agents.report_agent import generate_report

from backend.app.core.evidence_manager import summarize_evidence
from backend.app.core.crewai_investigator import (
    review_investigation_with_crew,
)

from backend.app.models.incident import IncidentRequest
from backend.app.models.evidence import Evidence

from backend.app.services.tsk_service import (
    list_filesystem_entries,
    extract_file_content,
)

from backend.app.services.ollama_service import analyze_forensic_artifact


logger = logging.getLogger("cyberguard.investigation")

MAX_ARTIFACTS_PER_IMAGE = 20
MAX_TEXT_ARTIFACT_BYTES = 10 * 1024

SUPPORTED_TEXT_EXTENSIONS = {
    ".txt",
    ".log",
    ".csv",
    ".xml",
    ".json",
    ".html",
    ".htm",
    ".ini",
    ".conf",
    ".cfg",
}

# These statuses indicate that a stage returned a result but did not
# finish successfully. They are different from an unhandled exception.
NON_SUCCESS_RESULT_STATUSES = {"failed", "incomplete"}


def _run_stage(
    stages: list[dict[str, Any]],
    stage_name: str,
    operation: Callable[[], Any],
) -> Any:
    """Run a stage and record its status and execution duration."""
    started = time.perf_counter()

    record = {
        "stage": stage_name,
        "status": "running",
        "duration_seconds": None,
    }
    stages.append(record)

    try:
        result = operation()
    except Exception as error:
        record["status"] = "failed"
        record["duration_seconds"] = round(
            time.perf_counter() - started, 4
        )
        record["error_type"] = type(error).__name__

        # Never log evidence contents, credentials, or exception messages.
        logger.error(
            "Investigation stage failed: stage=%s error_type=%s",
            stage_name,
            type(error).__name__,
        )
        raise

    # Some operations return a result dictionary describing their own
    # status instead of raising an exception. Respect that status.
    result_status = (
        result.get("status")
        if isinstance(result, dict)
        else None
    )

    if result_status in NON_SUCCESS_RESULT_STATUSES:
        record["status"] = result_status
    else:
        record["status"] = "completed"

    record["duration_seconds"] = round(
        time.perf_counter() - started, 4
    )

    if record["status"] == "completed":
        logger.info(
            "Investigation stage completed: stage=%s "
            "duration_seconds=%.4f",
            stage_name,
            record["duration_seconds"],
        )
    else:
        logger.warning(
            "Investigation stage returned non-success status: "
            "stage=%s status=%s duration_seconds=%.4f",
            stage_name,
            record["status"],
            record["duration_seconds"],
        )

    return result


def _collect_image_artifacts(
    image_path: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Collect a bounded number of supported text artifacts using TSK.

    No event timestamps are inferred from collection time or filenames.
    """
    image = Path(image_path).expanduser()

    if not image.is_absolute():
        raise ValueError(
            "Please provide an absolute local forensic image path."
        )

    listing = list_filesystem_entries(image)

    if not listing.get("success"):
        raise RuntimeError(
            "The Sleuth Kit could not list filesystem entries."
        )

    collected: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for line in listing.get("stdout", "").splitlines():
        if len(collected) >= MAX_ARTIFACTS_PER_IMAGE:
            break

        try:
            prefix, file_name = line.split(":", 1)
            prefix = prefix.strip()
            file_name = file_name.strip()
        except ValueError:
            continue

        # Process regular files only.
        if not prefix.startswith(("r/r ", "r/- ", "r/* ")):
            continue

        address_parts = prefix.split()

        if len(address_parts) < 2:
            errors.append({
                "path": file_name,
                "error": "Could not parse the TSK metadata address.",
            })
            continue

        address_text = address_parts[-1].split("-")[0]

        try:
            metadata_address = int(address_text)
        except ValueError:
            errors.append({
                "path": file_name,
                "error": "Invalid TSK metadata address.",
            })
            continue

        if Path(file_name).suffix.lower() not in SUPPORTED_TEXT_EXTENSIONS:
            continue

        try:
            extracted = extract_file_content(
                image_path=image,
                metadata_address=metadata_address,
                max_bytes=MAX_TEXT_ARTIFACT_BYTES,
            )

            if not extracted.get("success"):
                errors.append({
                    "metadata_address": metadata_address,
                    "path": file_name,
                    "error": "Artifact extraction failed.",
                })
                continue

            content = extracted.get("content", b"")

            if not isinstance(content, bytes):
                errors.append({
                    "metadata_address": metadata_address,
                    "path": file_name,
                    "error": "Extraction service did not return bytes.",
                })
                continue

            try:
                text_content = content.decode("utf-8")
            except UnicodeDecodeError:
                errors.append({
                    "metadata_address": metadata_address,
                    "path": file_name,
                    "error": "Artifact is not valid UTF-8 text.",
                })
                continue

            collected.append({
                "image_name": extracted.get("image_name", image.name),
                "metadata_address": metadata_address,
                "path": file_name,
                "text": text_content,
                "size_bytes": extracted.get("size_bytes", len(content)),
            })

        except (
            ValueError,
            FileNotFoundError,
            RuntimeError,
            TimeoutError,
        ) as error:
            errors.append({
                "metadata_address": metadata_address,
                "path": file_name,
                "error": f"Extraction failed: {type(error).__name__}",
            })

    return collected, errors


def run_investigation(request: IncidentRequest | dict) -> dict:
    """
    Run a CyberGuard investigation and record stage-level monitoring.

    Original evidence, deterministic checks, and AI interpretations
    remain distinguishable.
    """
    total_started = time.perf_counter()
    stages: list[dict[str, Any]] = []
    incident_id = str(uuid.uuid4())

    try:
        if isinstance(request, dict):
            request = IncidentRequest(**request)

        case = _run_stage(
            stages,
            "case_creation",
            lambda: create_case(
                request.title,
                request.description,
                request.investigation_goal,
            ),
        )

        plan = _run_stage(
            stages,
            "investigation_planning",
            lambda: create_investigation_plan(
                request.description,
                request.log_text,
            ),
        )

        log_evidence = _run_stage(
            stages,
            "log_analysis",
            lambda: investigate_logs(request.log_text),
        )

        def normalize_evidence() -> list[dict[str, Any]]:
            normalized = []

            for item in log_evidence:
                if isinstance(item, Evidence):
                    normalized.append(item.model_dump())
                elif isinstance(item, dict):
                    normalized.append(dict(item))
                else:
                    raise ValueError(
                        "The log agent returned an unsupported evidence type."
                    )

            return normalized

        evidence = _run_stage(
            stages,
            "evidence_normalization",
            normalize_evidence,
        )

        artifact_analyses: list[dict[str, Any]] = []
        collection_errors: list[dict[str, Any]] = []
        artifacts: list[dict[str, Any]] = []

        # Optionally collect artifacts from a forensic image.
        if request.image_path:

            def collect_artifacts() -> list[dict[str, Any]]:
                try:
                    found, extraction_errors = _collect_image_artifacts(
                        request.image_path
                    )
                    collection_errors.extend(extraction_errors)
                    return found

                except (
                    ValueError,
                    FileNotFoundError,
                    RuntimeError,
                    TimeoutError,
                ) as error:
                    collection_errors.append({
                        "path": request.image_path,
                        "error": (
                            f"Collection failed: {type(error).__name__}"
                        ),
                    })
                    return []

            artifacts = _run_stage(
                stages,
                "forensic_artifact_collection",
                collect_artifacts,
            )

            def register_artifacts() -> None:
                for artifact in artifacts:
                    metadata_address = artifact["metadata_address"]
                    artifact_path = artifact["path"]
                    image_name = artifact["image_name"]

                    artifact_id = (
                        f"IMG-{metadata_address}-"
                        f"{Path(artifact_path).name}"
                    )

                    # Preserve extracted evidence. Monitoring logs never
                    # contain original artifact text.
                    evidence.append(
                        Evidence(
                            evidence_id=artifact_id,
                            source=f"{image_name} :: {artifact_path}",
                            timestamp=None,
                            event_type="filesystem_artifact",
                            description=(
                                "Text artifact extracted from a forensic image. "
                                "The content requires investigator review."
                            ),
                            severity="low",
                            supporting=False,
                            metadata={
                                "image_name": image_name,
                                "path": artifact_path,
                                "metadata_address": metadata_address,
                                "size_bytes": artifact["size_bytes"],
                                "text_content": artifact["text"],
                                "timestamp_note": (
                                    "No original event timestamp was inferred."
                                ),
                            },
                        ).model_dump()
                    )

            _run_stage(
                stages,
                "artifact_evidence_registration",
                register_artifacts,
            )

            def analyze_artifacts() -> None:
                for artifact in artifacts:
                    metadata_address = artifact["metadata_address"]
                    artifact_path = artifact["path"]
                    image_name = artifact["image_name"]

                    artifact_id = (
                        f"IMG-{metadata_address}-"
                        f"{Path(artifact_path).name}"
                    )

                    try:
                        ai_result = analyze_forensic_artifact(
                            evidence_text=artifact["text"],
                            image_name=image_name,
                            metadata_address=metadata_address,
                        )

                        artifact_analyses.append({
                            "evidence_id": artifact_id,
                            "source": {
                                "image_name": image_name,
                                "path": artifact_path,
                                "metadata_address": metadata_address,
                            },
                            "ai_analysis": ai_result.get(
                                "ai_analysis", ""
                            ),
                            "warning": ai_result.get(
                                "warning",
                                (
                                    "AI-generated interpretation. "
                                    "Validate against the original evidence."
                                ),
                            ),
                        })

                    except (
                        ValueError,
                        RuntimeError,
                        TimeoutError,
                    ) as error:
                        collection_errors.append({
                            "metadata_address": metadata_address,
                            "path": artifact_path,
                            "error": (
                                "AI analysis failed: "
                                f"{type(error).__name__}"
                            ),
                        })

                        logger.warning(
                            "Artifact AI analysis failed: "
                            "evidence_id=%s error_type=%s",
                            artifact_id,
                            type(error).__name__,
                        )

            _run_stage(
                stages,
                "ollama_artifact_analysis",
                analyze_artifacts,
            )

        hypotheses = _run_stage(
            stages,
            "hypothesis_generation",
            lambda: generate_hypotheses(evidence),
        )

        hypotheses = _run_stage(
            stages,
            "hypothesis_verification",
            lambda: verify_hypotheses(hypotheses, evidence),
        )

        hypotheses = _run_stage(
            stages,
            "contradiction_analysis",
            lambda: find_contradictions(hypotheses, evidence),
        )

        timeline = _run_stage(
            stages,
            "timeline_creation",
            lambda: create_timeline(evidence),
        )

        crewai_review = _run_stage(
            stages,
            "crewai_review",
            lambda: review_investigation_with_crew(
                title=request.title,
                description=request.description,
                investigation_goal=request.investigation_goal,
                evidence=evidence,
                hypotheses=hypotheses,
                timeline=timeline,
            ),
        )

        report = _run_stage(
            stages,
            "report_generation",
            lambda: generate_report(
                request.title,
                request.description,
                evidence,
                hypotheses,
                crewai_analysis=crewai_review,
            ),
        )

        evidence_summary = _run_stage(
            stages,
            "evidence_summarization",
            lambda: summarize_evidence(evidence),
        )

        total_runtime = round(time.perf_counter() - total_started, 4)

        failed_stage_count = sum(
            stage["status"] == "failed" for stage in stages
        )
        incomplete_stage_count = sum(
            stage["status"] == "incomplete" for stage in stages
        )

        # Keep the overall investigation status separate from the AI review
        # status. An incomplete AI review does not erase valid evidence.
        if failed_stage_count:
            overall_status = "completed_with_errors"
        elif incomplete_stage_count:
            overall_status = "completed_with_warnings"
        else:
            overall_status = "completed"

        logger.info(
            "Investigation finished: incident_id=%s status=%s "
            "stage_count=%d failed_stages=%d incomplete_stages=%d "
            "total_runtime_seconds=%.4f",
            incident_id,
            overall_status,
            len(stages),
            failed_stage_count,
            incomplete_stage_count,
            total_runtime,
        )

        # Preserve the existing response fields for frontend compatibility.
        return {
            "incident_id": incident_id,
            "title": case["title"],
            "status": overall_status,
            "investigation_plan": plan,
            "evidence": evidence,
            "evidence_summary": evidence_summary,
            "hypotheses": hypotheses,
            "timeline": timeline,
            "report": report,
            "forensic_artifact_analyses": artifact_analyses,
            "crewai_review": crewai_review,
            "collection_errors": collection_errors,
            "monitoring": {
                "total_runtime_seconds": total_runtime,
                "stages": stages,
                "stage_count": len(stages),
                "failed_stage_count": failed_stage_count,
                "incomplete_stage_count": incomplete_stage_count,
                "model": os.getenv("OLLAMA_MODEL", "qwen2.5:3b"),
                "ollama_base_url": os.getenv(
                    "OLLAMA_BASE_URL",
                    "http://127.0.0.1:11434",
                ),
                "estimated_cost": None,
                "estimated_cost_note": (
                    "Cost is not measured by this local Ollama workflow."
                ),
            },
            "note": (
                "Rule-based and AI-assisted findings require human validation. "
                "AI interpretations are not verified forensic facts. "
                "Preserve the original evidence."
            ),
        }

    except Exception as error:
        total_runtime = round(time.perf_counter() - total_started, 4)

        logger.error(
            "Investigation failed: incident_id=%s error_type=%s "
            "elapsed_seconds=%.4f",
            incident_id,
            type(error).__name__,
            total_runtime,
        )
        raise
