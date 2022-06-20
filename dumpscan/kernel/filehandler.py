from io import RawIOBase
from pathlib import Path

from volatility3.framework.interfaces.plugins import FileHandlerInterface


class DumpscanFileHandler(FileHandlerInterface):
    """Handles writing files to disk"""

    output_dir: Path = Path(".")

    def __init__(self, filename: str) -> None:
        super().__init__(filename)

    def write(self, data: bytes) -> int | None:
        output_file: Path = self.output_dir / self._preferred_filename
        return output_file.write_bytes(data)
