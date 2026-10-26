from pathlib import Path


def read_text_file(path: str, max_bytes: int = 1_000_000) -> str:
    file_path = Path(path)

    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    data = file_path.read_bytes()

    if len(data) > max_bytes:
        raise ValueError("File exceeds the maximum allowed size")

    return data.decode("utf-8", errors="replace")