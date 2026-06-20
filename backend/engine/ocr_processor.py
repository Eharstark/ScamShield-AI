from __future__ import annotations

import logging
from pathlib import Path

from PIL import Image, ImageFilter, ImageOps
import pytesseract

logger = logging.getLogger(__name__)


class OCRProcessorError(Exception):
    """Raised when OCR processing fails."""


class OCRProcessor:

    SUPPORTED_EXTENSIONS = (
        ".png",
        ".jpg",
        ".jpeg",
        ".webp",
        ".bmp",
        ".tiff",
    )

    MIN_UPSCALE_WIDTH = 1000

    def __init__(
        self,
        tesseract_cmd: str | None = None,
        language: str = "eng",
    ) -> None:

        if tesseract_cmd:
            pytesseract.pytesseract.tesseract_cmd = tesseract_cmd
        else:
            pytesseract.pytesseract.tesseract_cmd = "/usr/bin/tesseract"

        self.language = language

        logger.info(
            "Using Tesseract binary: %s",
            pytesseract.pytesseract.tesseract_cmd,
        )

    def extract_text(self, image_path: str | Path) -> dict:

        path = Path(image_path)

        self._validate_path(path)

        image = self._load_image(path)

        image = self._preprocess(image)

        text = self._run_ocr(image)

        text = self._clean_text(text)

        return {
            "text": text,
            "char_count": len(text),
            "source": str(path),
        }

    def extract_text_from_image(self, image: Image.Image) -> dict:

        image = self._preprocess(image)

        text = self._run_ocr(image)

        text = self._clean_text(text)

        return {
            "text": text,
            "char_count": len(text),
            "source": "in-memory",
        }

    def _validate_path(self, path: Path) -> None:

        if not path.exists():
            raise OCRProcessorError(
                f"Image file not found: {path}"
            )

        if path.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
            raise OCRProcessorError(
                f"Unsupported image type: {path.suffix}"
            )

    def _load_image(self, path: Path) -> Image.Image:

        try:
            return Image.open(path)

        except Exception as exc:
            raise OCRProcessorError(
                f"Unable to open image: {exc}"
            ) from exc

    def _preprocess(self, image: Image.Image) -> Image.Image:

        try:
            image = image.convert("L")

            image = ImageOps.autocontrast(image)

            image = image.filter(ImageFilter.SHARPEN)

            if image.width < self.MIN_UPSCALE_WIDTH:

                scale = self.MIN_UPSCALE_WIDTH / image.width

                image = image.resize(
                    (
                        int(image.width * scale),
                        int(image.height * scale),
                    ),
                    Image.LANCZOS,
                )

            return image

        except Exception as exc:
            raise OCRProcessorError(
                f"Image preprocessing failed: {exc}"
            ) from exc

    def _run_ocr(self, image: Image.Image) -> str:

        try:

            logger.info(
                "Running OCR using %s",
                pytesseract.pytesseract.tesseract_cmd,
            )

            text = pytesseract.image_to_string(
                image,
                lang=self.language,
            )

            return text

        except pytesseract.TesseractNotFoundError as exc:

            raise OCRProcessorError(
                f"Tesseract not found at "
                f"{pytesseract.pytesseract.tesseract_cmd}"
            ) from exc

        except Exception as exc:

            raise OCRProcessorError(
                f"OCR failed: {exc}"
            ) from exc

    @staticmethod
    def _clean_text(text: str) -> str:

        lines = [line.strip() for line in text.splitlines()]

        lines = [line for line in lines if line]

        return "\n".join(lines)