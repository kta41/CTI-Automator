"""PDF text extraction with explicit document-level errors."""

from __future__ import annotations

from pathlib import Path

import pdfplumber

from cti_automator.exceptions import DocumentExtractionError


class PDFTextExtractor:
    """Extract readable text from all pages of a PDF report."""

    def __init__(
        self,
        *,
        max_bytes: int = 20_000_000,
        max_pages: int = 100,
    ) -> None:
        self._max_bytes = max_bytes
        self._max_pages = max_pages

    def extract(self, path: Path) -> str:
        """Return normalized text, failing when the document is unreadable."""
        if not path.is_file():
            raise DocumentExtractionError(f"PDF file does not exist: {path}")
        if path.suffix.lower() != ".pdf":
            raise DocumentExtractionError(f"expected a PDF file: {path}")
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise DocumentExtractionError(f"could not inspect PDF {path}") from exc
        if size > self._max_bytes:
            raise DocumentExtractionError("PDF exceeds configured byte limit")

        pages: list[str] = []
        try:
            with pdfplumber.open(path) as pdf:
                if len(pdf.pages) > self._max_pages:
                    raise DocumentExtractionError("PDF exceeds configured page limit")
                for page in pdf.pages:
                    text = page.extract_text()
                    if text:
                        pages.append(text)
        except DocumentExtractionError:
            raise
        except (OSError, ValueError, pdfplumber.pdfminer.pdfparser.PDFSyntaxError) as exc:
            raise DocumentExtractionError(f"could not read PDF {path}") from exc

        content = "\n\n".join(page.strip() for page in pages if page.strip())
        if not content:
            raise DocumentExtractionError(f"PDF contains no extractable text: {path}")
        return content
