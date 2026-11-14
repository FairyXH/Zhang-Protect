import base64
import io
from pathlib import Path
import sys

RESOURCE_CHUNK_SIZE = 1024 * 1024
RESOURCE_MAGIC = b"ZPRES\x01\r\n"


class EmbeddedResource:
    """A small reference to binary data collected by the PyInstaller hook."""

    __slots__ = ("name",)

    def __init__(self, name):
        if Path(name).name != name or name in ("", ".", ".."):
            raise ValueError("Invalid embedded resource name")
        self.name = name

    def open(self):
        root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
        source = (root / "_resource_data" / self.name).open("rb")
        if source.read(len(RESOURCE_MAGIC)) != RESOURCE_MAGIC:
            source.close()
            raise ValueError(f"Invalid embedded resource format: {self.name}")
        return source


def write_resource(output, resource):
    if isinstance(resource, EmbeddedResource):
        with resource.open() as source:
            while chunk := source.read(RESOURCE_CHUNK_SIZE):
                output.write(chunk)
        return
    # Keep compatibility with the existing base64 bytes and image strings.
    pending = b""
    for offset in range(0, len(resource), RESOURCE_CHUNK_SIZE):
        chunk = resource[offset : offset + RESOURCE_CHUNK_SIZE]
        if isinstance(chunk, str):
            chunk = chunk.encode("ascii")
        chunk = pending + b"".join(chunk.split())
        count = len(chunk) // 4 * 4
        if count:
            output.write(base64.b64decode(chunk[:count]))
        pending = chunk[count:]
    if pending:
        output.write(base64.b64decode(pending))


def read_resource(resource):
    """Read small resources that must be manipulated as bytes, such as proxies."""
    output = io.BytesIO()
    write_resource(output, resource)
    return output.getvalue()
