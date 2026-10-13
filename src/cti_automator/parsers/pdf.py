"""PDF text extraction with explicit document-level errors."""

from __future__ import annotations

from pathlib import Path

import pdfplumber

from cti_automator.exceptions import DocumentExtractionError


class PDFTextExtractor:
    """Extract readable text from all pages of a PDF report."""

    def extract(self, path: Path) -> str:
        """Return normalized text, failing when the document is unreadable."""
        if not path.is_file():
            raise DocumentExtractionError(f"PDF file does not exist: {path}")
        if path.suffix.lower() != ".pdf":
            raise DocumentExtractionError(f"expected a PDF file: {path}")

        pages: list[str] = []
        try:
            with pdfplumber.open(path) as pdf:
                for page in pdf.pages:
                    text = page.extract_text()
                    if text:
                        pages.append(text)
        except (OSError, ValueError, pdfplumber.pdfminer.pdfparser.PDFSyntaxError) as exc:
            raise DocumentExtractionError(f"could not read PDF {path}") from exc

        content = "\n\n".join(page.strip() for page in pages if page.strip())
        if not content:
            raise DocumentExtractionError(f"PDF contains no extractable text: {path}")
        return content
