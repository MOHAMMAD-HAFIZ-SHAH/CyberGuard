
import uuid
from pathlib import Path

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


def _collect_image_artifacts(
    image_path: str,
) -> tuple[list[dict], list[dict]]:
    """
    Collect a bounded number of supported text artifacts from a
    forensic image using The Sleuth Kit.

    Original timestamps are not inferred from collection time,
    filenames, or AI interpretation.
    """
    image = Path(image_path).expanduser()

    if not image.is_absolute():
        raise ValueError(
            "Please provide an absolute local forensic image path."
        )

    listing = list_filesystem_entries(image)

    if not listing.get("success"):
        raise RuntimeError(
            "The Sleuth Kit could not list filesystem entries: "
            + (
                listing.get("stderr")
                or listing.get("error")
                or "Unknown TSK error"
            )
        )

    collected: list[dict] = []
    errors: list[dict] = []

    listing_text = listing.get("stdout", "")

    for line in listing_text.splitlines():
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

        address_text = address_parts[-1]

        # Remove an optional TSK metadata type suffix.
        address_text = address_text.split("-")[0]

        try:
            metadata_address = int(address_text)
        except ValueError:
            errors.append({
                "path": file_name,
                "error": f"Invalid metadata address: {address_text}",
            })
            continue

        extension = Path(file_name).suffix.lower()

        if extension not in SUPPORTED_TEXT_EXTENSIONS:
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
                    "error": extracted.get(
                        "error",
                        "Artifact extraction failed.",
                    ),
                })
                continue

            content = extracted.get("content", b"")

            if not isinstance(content, bytes):
                errors.append({
                    "metadata_address": metadata_address,
                    "path": file_name,
                    "error": (
                        "The extraction service did not return bytes."
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
                "error": str(error),
            })

    return collected, errors


def run_investigation(request: IncidentRequest) -> dict:
    """
    Run a CyberGuard investigation using supplied logs and,
    optionally, a local forensic disk image.

    CrewAI analysis is incorporated into the existing final report.
    Original evidence, deterministic checks, and AI interpretations
    remain distinguishable.
    """
    if isinstance(request, dict):
        request = IncidentRequest(**request)

    incident_id = str(uuid.uuid4())

    case = create_case(
        request.title,
        request.description,
        request.investigation_goal,
    )

    plan = create_investigation_plan(
        request.description,
        request.log_text,
    )

    # 1. Analyze supplied logs using the existing log agent.
    log_evidence = investigate_logs(request.log_text)

    # 2. Normalize evidence into dictionaries for downstream agents.
    evidence: list[dict] = []

    for item in log_evidence:
        if isinstance(item, Evidence):
            evidence.append(item.model_dump())
        elif isinstance(item, dict):
            evidence.append(dict(item))
        else:
            raise ValueError(
                "The log agent returned an unsupported evidence type."
            )

    artifact_analyses: list[dict] = []
    collection_errors: list[dict] = []

    # 3. Optionally collect forensic artifacts from a disk image.
    if request.image_path:
        try:
            artifacts, extraction_errors = _collect_image_artifacts(
                request.image_path
            )
            collection_errors.extend(extraction_errors)

        except (
            ValueError,
            FileNotFoundError,
            RuntimeError,
            TimeoutError,
        ) as error:
            artifacts = []
            collection_errors.append({
                "path": request.image_path,
                "error": str(error),
            })

        for artifact in artifacts:
            metadata_address = artifact["metadata_address"]
            artifact_path = artifact["path"]
            image_name = artifact["image_name"]

            artifact_id = (
                f"IMG-{metadata_address}-"
                f"{Path(artifact_path).name}"
            )

            # Preserve extracted content separately from AI interpretation.
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

            # Retain the existing Ollama artifact analysis.
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
                collection_errors.append({
                    "metadata_address": metadata_address,
                    "path": artifact_path,
                    "error": f"AI analysis failed: {error}",
                })

    # 4. Run existing hypothesis and verification agents.
    hypotheses = generate_hypotheses(evidence)
    hypotheses = verify_hypotheses(hypotheses, evidence)
    hypotheses = find_contradictions(hypotheses, evidence)

    # 5. Build the existing event timeline.
    timeline = create_timeline(evidence)

    # 6. Run CrewAI BEFORE generating the final report.
    # Its output is advisory and does not replace evidence verification.
    crewai_review = review_investigation_with_crew(
        title=request.title,
        description=request.description,
        evidence=evidence,
    )

    # 7. Generate one unified report with CrewAI analysis integrated.
    # The report agent keeps AI interpretations distinct from verified facts.
    report = generate_report(
        request.title,
        request.description,
        evidence,
        hypotheses,
        crewai_analysis=crewai_review,
    )

    # 8. Return the complete investigation result.
    return {
        "incident_id": incident_id,
        "title": case["title"],
        "status": "completed",
        "investigation_plan": plan,
        "evidence": evidence,
        "evidence_summary": summarize_evidence(evidence),
        "hypotheses": hypotheses,
        "timeline": timeline,
        "report": report,
        "forensic_artifact_analyses": artifact_analyses,
        "crewai_review": crewai_review,
        "collection_errors": collection_errors,
        "note": (
            "Rule-based and AI-assisted findings require human validation. "
            "AI interpretations are not verified forensic facts. "
            "Preserve the original evidence."
        ),
    }
