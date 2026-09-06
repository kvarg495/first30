from io import BytesIO

import pytest
from PIL import Image

from src.utils.images import ImageValidationError, normalize_uploads


class FakeUpload:
    def __init__(self, name: str, media_type: str, data: bytes) -> None:
        self.name = name
        self.type = media_type
        self._data = data

    def getvalue(self) -> bytes:
        return self._data


def image_bytes(image_format: str = "PNG", size: tuple[int, int] = (80, 60)) -> bytes:
    buffer = BytesIO()
    Image.new("RGB", size, "navy").save(buffer, format=image_format)
    return buffer.getvalue()


def test_image_is_validated_reencoded_and_kept_in_memory() -> None:
    result = normalize_uploads([FakeUpload("evidence.png", "image/png", image_bytes())])
    assert len(result) == 1
    assert result[0].media_type == "image/jpeg"
    assert result[0].width == 80
    assert result[0].metadata().analysis_status == "not_analysed"


def test_oversized_and_corrupt_uploads_are_rejected() -> None:
    with pytest.raises(ImageValidationError, match="5 MB"):
        normalize_uploads([FakeUpload("large.png", "image/png", b"0" * (5 * 1024 * 1024 + 1))])
    with pytest.raises(ImageValidationError, match="corrupt"):
        normalize_uploads([FakeUpload("fake.png", "image/png", b"not an image")])


def test_no_more_than_five_images_are_accepted() -> None:
    upload = FakeUpload("small.png", "image/png", image_bytes())
    with pytest.raises(ImageValidationError, match="no more than 5"):
        normalize_uploads([upload] * 6)
