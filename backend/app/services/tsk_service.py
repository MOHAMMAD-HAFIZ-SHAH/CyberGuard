
import os
import shutil
import subprocess
from pathlib import Path

SUPPORTED_IMAGE_EXTENSIONS = {".dd", ".img", ".raw", ".e01"}
ALLOWED_TOOLS = {"mmls", "fls", "fsstat", "icat"}

COMMAND_TIMEOUT_SECONDS = 120
MAX_OUTPUT_CHARS = 2_000_000
MAX_EXTRACT_BYTES = 10 * 1024 * 1024


def validate_image(image_path: str | Path) -> Path:
    """Validate the path and basic properties of a forensic image."""
    path = Path(image_path).expanduser().resolve(strict=True)

    if not path.is_file():
        raise ValueError("The supplied path must point to a file.")

    if path.suffix.lower() not in SUPPORTED_IMAGE_EXTENSIONS:
        raise ValueError(
            f"Unsupported image extension: {path.suffix}. "
            "Supported extensions: .dd, .img, .raw, .e01"
        )

    if path.stat().st_size <= 0:
        raise ValueError("The forensic image is empty.")

    return path


def find_tsk_tool(tool_name: str) -> str:
    """Find an approved Sleuth Kit executable."""
    if tool_name not in ALLOWED_TOOLS:
        raise ValueError(f"Unsupported Sleuth Kit tool: {tool_name}")

    executable_name = (
        f"{tool_name}.exe" if os.name == "nt" else tool_name
    )

    configured_directory = os.getenv("TSK_BIN_DIR")

    if configured_directory:
        candidate = Path(configured_directory) / executable_name
        if candidate.is_file():
            return str(candidate.resolve())

    found = shutil.which(executable_name)
    if found:
        return found

    raise FileNotFoundError(
        f"{executable_name} was not found. "
        "Set TSK_BIN_DIR to the folder containing the Sleuth Kit executables."
    )


def run_tsk(
    tool_name: str,
    arguments: list[str],
    timeout: int = COMMAND_TIMEOUT_SECONDS,
) -> dict:
    """Run an approved TSK tool without invoking a command shell."""
    if tool_name not in ALLOWED_TOOLS:
        raise ValueError(f"Unsupported Sleuth Kit tool: {tool_name}")

    if not isinstance(arguments, list) or not all(
        isinstance(arg, str) for arg in arguments
    ):
        raise ValueError("Arguments must be a list of strings.")

    executable = find_tsk_tool(tool_name)

    try:
        completed = subprocess.run(
            [executable, *arguments],
            shell=False,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise TimeoutError(
            f"{tool_name} exceeded its {timeout}-second timeout."
        ) from error

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""

    return {
        "tool": tool_name,
        "return_code": completed.returncode,
        "success": completed.returncode == 0,
        "stdout": stdout[:MAX_OUTPUT_CHARS],
        "stderr": stderr[:MAX_OUTPUT_CHARS],
        "output_truncated": (
            len(stdout) > MAX_OUTPUT_CHARS
            or len(stderr) > MAX_OUTPUT_CHARS
        ),
    }


def inspect_partitions(image_path: str | Path) -> dict:
    """Return TSK partition information for an image."""
    image = validate_image(image_path)
    result = run_tsk("mmls", [str(image)])

    return {
        "image_name": image.name,
        **result,
    }


def inspect_filesystem(
    image_path: str | Path,
    partition_offset: int | None = None,
) -> dict:
    """Return filesystem metadata, optionally at a partition offset."""
    image = validate_image(image_path)
    arguments: list[str] = []

    if partition_offset is not None:
        if isinstance(partition_offset, bool) or not isinstance(
            partition_offset, int
        ):
            raise ValueError("Partition offset must be an integer.")

        if partition_offset < 0:
            raise ValueError("Partition offset cannot be negative.")

        arguments.extend(["-o", str(partition_offset)])

    arguments.append(str(image))
    result = run_tsk("fsstat", arguments)

    return {
        "image_name": image.name,
        "partition_offset_sectors": partition_offset,
        **result,
    }


def list_deleted_entries(
    image_path: str | Path,
    partition_offset: int | None = None,
) -> dict:
    """List deleted filesystem entries reported by TSK."""
    image = validate_image(image_path)
    arguments = ["-r", "-d"]

    if partition_offset is not None:
        if isinstance(partition_offset, bool) or not isinstance(
            partition_offset, int
        ):
            raise ValueError("Partition offset must be an integer.")

        if partition_offset < 0:
            raise ValueError("Partition offset cannot be negative.")

        arguments.extend(["-o", str(partition_offset)])

    arguments.append(str(image))
    result = run_tsk("fls", arguments)

    return {
        "image_name": image.name,
        "partition_offset_sectors": partition_offset,
        **result,
    }


def list_filesystem_entries(
    image_path: str | Path,
    partition_offset: int | None = None,
) -> dict:
    """List filesystem entries recursively using The Sleuth Kit."""
    image = validate_image(image_path)
    arguments = ["-r"]

    if partition_offset is not None:
        if isinstance(partition_offset, bool) or not isinstance(
            partition_offset, int
        ):
            raise ValueError("Partition offset must be an integer.")

        if partition_offset < 0:
            raise ValueError("Partition offset cannot be negative.")

        arguments.extend(["-o", str(partition_offset)])

    arguments.append(str(image))
    result = run_tsk("fls", arguments)

    return {
        "image_name": image.name,
        "partition_offset_sectors": partition_offset,
        **result,
    }


def extract_file_content(
    image_path: str | Path,
    metadata_address: int,
    partition_offset: int | None = None,
    max_bytes: int = MAX_EXTRACT_BYTES,
) -> dict:
    """Extract file bytes by TSK metadata address using icat."""
    image = validate_image(image_path)

    if isinstance(metadata_address, bool) or not isinstance(
        metadata_address, int
    ):
        raise ValueError("Metadata address must be an integer.")

    if metadata_address < 0:
        raise ValueError("Metadata address cannot be negative.")

    if partition_offset is not None:
        if isinstance(partition_offset, bool) or not isinstance(
            partition_offset, int
        ):
            raise ValueError("Partition offset must be an integer.")

        if partition_offset < 0:
            raise ValueError("Partition offset cannot be negative.")

    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
        raise ValueError("Maximum extraction size must be an integer.")

    if max_bytes <= 0 or max_bytes > MAX_EXTRACT_BYTES:
        raise ValueError(
            f"Maximum extraction size must be between 1 and "
            f"{MAX_EXTRACT_BYTES} bytes."
        )

    arguments: list[str] = []

    if partition_offset is not None:
        arguments.extend(["-o", str(partition_offset)])

    # Correct icat syntax: icat [options] image metadata_address
    arguments.extend([str(image), str(metadata_address)])

    executable = find_tsk_tool("icat")

    try:
        completed = subprocess.run(
            [executable, *arguments],
            shell=False,
            capture_output=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise TimeoutError(
            f"icat exceeded its {COMMAND_TIMEOUT_SECONDS}-second timeout."
        ) from error

    if completed.returncode != 0:
        error_text = (completed.stderr or b"").decode(
            "utf-8", errors="replace"
        )[:4000]

        return {
            "image_name": image.name,
            "metadata_address": metadata_address,
            "partition_offset_sectors": partition_offset,
            "success": False,
            "return_code": completed.returncode,
            "error": (
                error_text
                or "TSK could not extract this metadata address."
            ),
        }

    content = completed.stdout or b""

    if len(content) > max_bytes:
        return {
            "image_name": image.name,
            "metadata_address": metadata_address,
            "partition_offset_sectors": partition_offset,
            "success": False,
            "error": (
                f"Extracted content exceeds the configured "
                f"{max_bytes}-byte limit."
            ),
            "size_bytes": len(content),
        }

    return {
        "image_name": image.name,
        "metadata_address": metadata_address,
        "partition_offset_sectors": partition_offset,
        "success": True,
        "size_bytes": len(content),
        "content": content,
        "warning": (
            "Extracted bytes are untrusted evidence. Validate file type "
            "and content before opening or processing them."
        ),
    }
