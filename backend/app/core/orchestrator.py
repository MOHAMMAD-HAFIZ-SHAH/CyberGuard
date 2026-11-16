import asyncio
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
from backend.app.agents.forensic_agent import analyze_forensic_evidence
from backend.app.agents.threat_agent import map_known_patterns
from backend.app.agents.endpoint_agent import analyze_endpoint_evidence

from backend.app.core.crew_agents import run_crew_agent
from backend.app.core.evidence_manager import summarize_evidence
from backend.app.core.crewai_investigator import (
    review_investigation_with_crew,
)

from backend.app.models.incident import IncidentRequest, IncidentResult
from backend.app.models.evidence import Evidence
from backend.app.models.hypothesis import Hypothesis

from backend.app.services.protocol_clients import call_a2a_review

from backend.app.services.tsk_service import (
    list_filesystem_entries,
    extract_file_content,
)

from backend.app.services.ollama_service import analyze_forensic_artifact
try:
    from backend.app.adk.adk_service import review_investigation
except ImportError:
    review_investigation = None


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

NON_SUCCESS_RESULT_STATUSES = {"failed", "incomplete"}


A2A_EVIDENCE_FIELDS = (
    "evidence_id",
    "source",
    "timestamp",
    "event_type",
    "description",
    "severity",
)

A2A_HYPOTHESIS_FIELDS = (
    "hypothesis_id",
    "description",
    "status",
    "confidence",
    "supporting_evidence",
    "contradicting_evidence",
)

A2A_TIMELINE_FIELDS = (
    "evidence_id",
    "source",
    "timestamp",
    "event_type",
    "description",
    "severity",
)


def _run_stage(
    stages: list[dict[str, Any]],
    stage_name: str,
    operation: Callable[[], Any],
) -> Any:
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
            time.perf_counter() - started,
            4,
        )
        record["error_type"] = type(error).__name__

        logger.error(
            "Investigation stage failed: stage=%s error_type=%s",
            stage_name,
            type(error).__name__,
        )

        raise

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
        time.perf_counter() - started,
        4,
    )

    if record["status"] == "completed":
        logger.info(
            "Investigation stage completed: stage=%s duration_seconds=%.4f",
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


def _agent_stage(
    stages: list[dict[str, Any]],
    agent_runs: list[dict[str, Any]],
    stage_name: str,
    agent_name: str,
    function: Callable[[], Any],
    context: str = "",
) -> Any:

    def operation() -> Any:
        result, run_info = run_crew_agent(
            agent_name,
            function,
            context,
        )

        run_info["stage"] = stage_name
        agent_runs.append(run_info)

        return result

    return _run_stage(
        stages,
        stage_name,
        operation,
    )


def _validate_evidence(
    items: list[Any],
) -> list[dict[str, Any]]:

    validated = []

    for item in items:

        if isinstance(item, Evidence):
            validated.append(item.model_dump())

        elif isinstance(item, dict):
            validated.append(
                Evidence(**item).model_dump()
            )

        else:
            raise ValueError(
                "Unsupported evidence type returned by an agent."
            )

    return validated


def _validate_hypotheses(
    items: list[Any],
) -> list[dict[str, Any]]:

    validated = []

    for item in items:

        if isinstance(item, Hypothesis):
            validated.append(item.model_dump())

        elif isinstance(item, dict):
            validated.append(
                Hypothesis(**item).model_dump()
            )

        else:
            raise ValueError(
                "Unsupported hypothesis type returned by an agent."
            )

    return validated


def _as_dict(item: Any) -> dict[str, Any]:

    if isinstance(item, dict):
        return item

    if hasattr(item, "model_dump"):
        value = item.model_dump(mode="json")

        if isinstance(value, dict):
            return value

    raise ValueError(
        "A review record must be a dictionary or Pydantic model."
    )


def _select_fields(
    items: list[Any],
    allowed_fields: tuple[str, ...],
) -> list[dict[str, Any]]:

    selected = []

    for item in items:

        record = _as_dict(item)

        selected.append({
            key: record[key]
            for key in allowed_fields
            if key in record
        })

    return selected


def _build_a2a_review_payload(
    evidence: list[Any],
    hypotheses: list[Any],
    timeline: list[Any],
) -> dict[str, Any]:

    return {
        "evidence": _select_fields(
            evidence,
            A2A_EVIDENCE_FIELDS,
        ),
        "hypotheses": _select_fields(
            hypotheses,
            A2A_HYPOTHESIS_FIELDS,
        ),
        "timeline": _select_fields(
            timeline,
            A2A_TIMELINE_FIELDS,
        ),
    }


def _collect_image_artifacts(
    image_path: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:

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

    listing_text = listing.get("stdout", "")

    if not isinstance(listing_text, str):
        raise RuntimeError(
            "The Sleuth Kit listing did not contain text output."
        )

    collected: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for line in listing_text.splitlines():

        if len(collected) >= MAX_ARTIFACTS_PER_IMAGE:
            break

        try:
            prefix, file_name = line.split(":", 1)

            prefix = prefix.strip()
            file_name = file_name.strip()

        except ValueError:
            continue

        if not prefix.startswith(("r/r ", "r/- ", "r/* ")):
            continue

        if (
            Path(file_name).suffix.lower()
            not in SUPPORTED_TEXT_EXTENSIONS
        ):
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
                    "error": (
                        "Extraction service did not return bytes."
                    ),
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
                "image_name": extracted.get(
                    "image_name",
                    image.name,
                ),
                "metadata_address": metadata_address,
                "path": file_name,
                "text": text_content,
                "size_bytes": extracted.get(
                    "size_bytes",
                    len(content),
                ),
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
                "error": (
                    f"Extraction failed: {type(error).__name__}"
                ),
            })

    return collected, errors


def run_investigation(
    request: IncidentRequest | dict,
) -> dict[str, Any]:

    total_started = time.perf_counter()

    stages: list[dict[str, Any]] = []
    agent_runs: list[dict[str, Any]] = []

    incident_id = str(uuid.uuid4())

    try:

        if isinstance(request, dict):
            request = IncidentRequest(**request)

        elif not isinstance(request, IncidentRequest):
            raise TypeError(
                "Invalid incident request type."
            )

        case = _agent_stage(
            stages,
            agent_runs,
            "case_creation",
            "case_manager",
            lambda: create_case(
                request.title,
                request.description,
                request.investigation_goal,
            ),
        )

        plan = _agent_stage(
            stages,
            agent_runs,
            "investigation_planning",
            "planner",
            lambda: create_investigation_plan(
                request.description,
                request.log_text,
            ),
        )

        log_evidence = _agent_stage(
            stages,
            agent_runs,
            "log_analysis",
            "log_agent",
            lambda: investigate_logs(
                request.log_text
            ),
        )

        evidence = _run_stage(
            stages,
            "evidence_normalization",
            lambda: _validate_evidence(log_evidence),
        )

        artifact_analyses: list[dict[str, Any]] = []
        collection_errors: list[dict[str, Any]] = []
        artifacts: list[dict[str, Any]] = []

        if request.image_path:

            def collect_artifacts() -> dict[str, Any]:

                try:
                    found, extraction_errors = (
                        _collect_image_artifacts(
                            request.image_path
                        )
                    )

                    collection_errors.extend(
                        extraction_errors
                    )

                    return {
                        "status": (
                            "incomplete"
                            if extraction_errors
                            else "completed"
                        ),
                        "artifacts": found,
                    }

                except Exception as error:

                    logger.warning(
                        "Forensic artifact collection failed: "
                        "error_type=%s",
                        type(error).__name__,
                    )

                    collection_errors.append({
                        "path": request.image_path,
                        "error": (
                            "Collection failed: "
                            f"{type(error).__name__}"
                        ),
                    })

                    return {
                        "status": "incomplete",
                        "artifacts": [],
                    }

            collection_result = _run_stage(
                stages,
                "forensic_artifact_collection",
                collect_artifacts,
            )

            artifacts = collection_result.get(
                "artifacts",
                [],
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

                    artifact_evidence = Evidence(
                        evidence_id=artifact_id,
                        source=(
                            f"{image_name} :: {artifact_path}"
                        ),
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
                    )

                    evidence.append(
                        artifact_evidence.model_dump()
                    )

            _run_stage(
                stages,
                "artifact_evidence_registration",
                register_artifacts,
            )

            def analyze_artifacts() -> dict[str, str]:

                analysis_failed = False

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
                                "ai_analysis",
                                "",
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

                        analysis_failed = True

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

                return {
                    "status": (
                        "incomplete"
                        if analysis_failed
                        else "completed"
                    )
                }

            _run_stage(
                stages,
                "ollama_artifact_analysis",
                analyze_artifacts,
            )

        forensic_findings = _agent_stage(
            stages,
            agent_runs,
            "forensic_indicator_analysis",
            "forensic_agent",
            lambda: analyze_forensic_evidence(evidence),
        )

        endpoint_findings = _agent_stage(
            stages,
            agent_runs,
            "endpoint_analysis",
            "endpoint_agent",
            lambda: analyze_endpoint_evidence(evidence),
        )

        threat_findings = _agent_stage(
            stages,
            agent_runs,
            "threat_pattern_mapping",
            "threat_agent",
            lambda: map_known_patterns(evidence),
        )

        hypotheses = _agent_stage(
            stages,
            agent_runs,
            "hypothesis_generation",
            "hypothesis_agent",
            lambda: generate_hypotheses(evidence),
        )

        hypotheses = _run_stage(
            stages,
            "hypothesis_validation",
            lambda: _validate_hypotheses(hypotheses),
        )

        hypotheses = _agent_stage(
            stages,
            agent_runs,
            "hypothesis_verification",
            "verification_agent",
            lambda: verify_hypotheses(
                hypotheses,
                evidence,
            ),
        )

        hypotheses = _run_stage(
            stages,
            "verified_hypothesis_validation",
            lambda: _validate_hypotheses(hypotheses),
        )

        hypotheses = _agent_stage(
            stages,
            agent_runs,
            "contradiction_analysis",
            "contradiction_agent",
            lambda: find_contradictions(
                hypotheses,
                evidence,
            ),
        )

        hypotheses = _run_stage(
            stages,
            "final_hypothesis_validation",
            lambda: _validate_hypotheses(hypotheses),
        )

        timeline = _agent_stage(
            stages,
            agent_runs,
            "timeline_creation",
            "timeline_agent",
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

        def perform_a2a_review() -> dict[str, Any]:

            try:
                review_payload = _build_a2a_review_payload(
                    evidence,
                    hypotheses,
                    timeline,
                )

                result = call_a2a_review(
                    review_payload
                )

                if not isinstance(result, dict):
                    raise ValueError(
                        "A2A reviewer returned an invalid response format."
                    )

                return result

            except Exception as error:

                logger.exception(
                    "A2A review unavailable: error_type=%s",
                    type(error).__name__,
                )

                return {
                    "status": "incomplete",
                    "review_agent": (
                        "CyberGuard A2A Forensic Reviewer"
                    ),
                    "review_status": "unavailable",
                    "findings": [],
                    "error_type": type(error).__name__,
                    "warning": (
                        "A2A review was unavailable. "
                        "The main investigation results were retained."
                    ),
                }

        a2a_review = _run_stage(
            stages,
            "a2a_forensic_review",
            perform_a2a_review,
        )

        report = _agent_stage(
            stages,
            agent_runs,
            "report_generation",
            "report_agent",
            lambda: generate_report(
                request.title,
                request.description,
                evidence,
                hypotheses,
                crewai_analysis=crewai_review,
            ),
        )

        def perform_adk_review() -> dict[str, Any]:
            try:
                review = asyncio.run(
                    review_investigation(
                        evidence=evidence,
                        hypotheses=hypotheses,
                        timeline=timeline,
                        report=report,
                        crewai_review=crewai_review,
                        incident_id=incident_id,
                    )
                )

                return {
                    "status": "completed",
                    "review": review.model_dump(mode="json"),
                }

            except Exception as error:
                logger.exception(
                    "Google ADK review unavailable: "
                    "incident_id=%s error_type=%s",
                    incident_id,
                    type(error).__name__,
                )

                return {
                    "status": "incomplete",
                    "review": {
                        "review_status": "unavailable",
                        "overall_assessment": (
                            "The Google ADK reviewer could not complete "
                            "this review. The investigation results were retained."
                        ),
                        "claim_assessments": [],
                        "hypothesis_issues": [],
                        "timeline_issues": [],
                        "missing_evidence": [],
                        "recommendations": [
                            "Retry the ADK review when the local Ollama "
                            "service is available."
                        ],
                        "limitations": [
                            "An independent Google ADK review was not completed."
                        ],
                        "human_review_required": True,
                        "error_type": type(error).__name__,
                    },
                }

        adk_stage_result = _run_stage(
            stages,
            "google_adk_forensic_review",
            perform_adk_review,
        )
        adk_review = adk_stage_result["review"]

        evidence_summary = _run_stage(
            stages,
            "evidence_summarization",
            lambda: summarize_evidence(evidence),
        )

        total_runtime = round(
            time.perf_counter() - total_started,
            4,
        )

        failed_stage_count = sum(
            stage["status"] == "failed"
            for stage in stages
        )

        incomplete_stage_count = sum(
            stage["status"] == "incomplete"
            for stage in stages
        )

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

        monitoring = {
            "total_runtime_seconds": total_runtime,
            "stages": stages,
            "stage_count": len(stages),
            "failed_stage_count": failed_stage_count,
            "incomplete_stage_count": incomplete_stage_count,
            "model": os.getenv(
                "OLLAMA_MODEL",
                "qwen2.5:3b",
            ),
            "ollama_base_url": os.getenv(
                "OLLAMA_BASE_URL",
                "http://127.0.0.1:11434",
            ),
            "estimated_cost": None,
            "estimated_cost_note": (
                "Cost is not measured by this local Ollama workflow."
            ),
        }

        result_data = {
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
            "a2a_review": a2a_review,
            "crew_agents": agent_runs,
            "agent_findings": {
                "forensic": forensic_findings,
                "endpoint": endpoint_findings,
                "threat": threat_findings,
            },
            "collection_errors": collection_errors,
            "monitoring": monitoring,
            "note": (
                "Rule-based and AI-assisted findings require human validation. "
                "AI interpretations are not verified forensic facts. "
                "Preserve the original evidence."
            ),
        }

        validated_result = IncidentResult.model_validate(
            result_data
        )

        final_result = validated_result.model_dump(
            mode="json"
        )
        final_result["adk_review"] = adk_review

        return final_result

    except Exception as error:

        total_runtime = round(
            time.perf_counter() - total_started,
            4,
        )

        logger.error(
            "Investigation failed: incident_id=%s error_type=%s "
            "elapsed_seconds=%.4f",
            incident_id,
            type(error).__name__,
            total_runtime,
        )

        raise
