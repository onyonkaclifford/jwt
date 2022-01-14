import base64
import json
from typing import Union


def encode(data: Union[dict, str]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def decode(data: str) -> Union[dict, str]:
    needs_padding = len(data) % 4

    if needs_padding:
        padding_size = 4 - needs_padding
        data += "=" * padding_size

    return json.loads(base64.urlsafe_b64decode(data).decode())
