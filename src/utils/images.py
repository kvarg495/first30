from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from typing import Protocol, Sequence

from PIL import Image, ImageOps, UnidentifiedImageError

from src.state import ImageMetadata


MAX_IMAGE_COUNT = 5
MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_TOTAL_BYTES = 20 * 1024 * 1024
MAX_IMAGE_DIMENSION = 2048
SUPPORTED_MEDIA_TYPES = {"image/png", "image/jpeg", "image/webp"}
FORMAT_MEDIA_TYPES = {"PNG": "image/png", "JPEG": "image/jpeg", "WEBP": "image/webp"}


class UploadedImage(Protocol):
    name: str
    type: str

    def getvalue(self) -> bytes: ...


class ImageValidationError(ValueError):
    pass


@dataclass(frozen=True)
class NormalizedImage:
    name: str
    media_type: str
    data: bytes
    width: int
    height: int

    def metadata(self, analysed: bool = False) -> ImageMetadata:
        return ImageMetadata(
            name=self.name,
            media_type=self.media_type,
            size_bytes=len(self.data),
            width=self.width,
            height=self.height,
            analysis_status="analysed" if analysed else "not_analysed",
        )


def normalize_uploads(uploads: Sequence[UploadedImage] | None) -> list[NormalizedImage]:
    """Validate and sanitise user images without writing them to disk."""
    items = list(uploads or [])
    if len(items) > MAX_IMAGE_COUNT:
        raise ImageValidationError(f"Upload no more than {MAX_IMAGE_COUNT} screenshots.")

    raw_total = sum(len(item.getvalue()) for item in items)
    if raw_total > MAX_TOTAL_BYTES:
        raise ImageValidationError("Screenshots exceed the 20 MB total limit.")

    normalised: list[NormalizedImage] = []
    for upload in items:
        raw = upload.getvalue()
        if not raw:
            raise ImageValidationError(f"{upload.name} is empty.")
        if len(raw) > MAX_IMAGE_BYTES:
            raise ImageValidationError(f"{upload.name} exceeds the 5 MB per-image limit.")
        if upload.type not in SUPPORTED_MEDIA_TYPES:
            raise ImageValidationError(f"{upload.name} is not a supported PNG, JPG, or WebP image.")

        try:
            with Image.open(BytesIO(raw)) as source:
                source.load()
                detected_type = FORMAT_MEDIA_TYPES.get(source.format or "")
                if detected_type not in SUPPORTED_MEDIA_TYPES:
                    raise ImageValidationError(f"{upload.name} has unsupported image content.")
                image = ImageOps.exif_transpose(source).copy()
        except (UnidentifiedImageError, OSError, ValueError) as exc:
            if isinstance(exc, ImageValidationError):
                raise
            raise ImageValidationError(f"{upload.name} is corrupt or is not a valid image.") from exc

        image.thumbnail((MAX_IMAGE_DIMENSION, MAX_IMAGE_DIMENSION), Image.Resampling.LANCZOS)
        # Re-encoding strips EXIF and other metadata. JPEG is compact for opaque
        # screenshots; PNG preserves transparency when it is present.
        has_alpha = "A" in image.getbands()
        output_type = "image/png" if has_alpha else "image/jpeg"
        output_format = "PNG" if has_alpha else "JPEG"
        clean = image.convert("RGBA" if has_alpha else "RGB")
        buffer = BytesIO()
        clean.save(buffer, format=output_format, optimize=True, quality=88)
        clean_bytes = buffer.getvalue()
        normalised.append(
            NormalizedImage(
                name=upload.name,
                media_type=output_type,
                data=clean_bytes,
                width=clean.width,
                height=clean.height,
            )
        )

    return normalised
