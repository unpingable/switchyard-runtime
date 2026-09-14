from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from switchyard.submission_protocol import (
    NightshiftPacket,
    canonical_json,
    nightshift_plan_ref,
    nightshift_preimage_digest,
    packet_from_json,
)

ROOT = Path(__file__).resolve().parents[1]
PINNED_PACKET = ROOT / "tests/fixtures/nightshift.orientation-packet.positive.v1.json"
PINNED_DIGEST = "01e9f695fd89af789023cea0b9220a8e5178f807066779c9f7a4b7b3b67d4ba7"
PINNED_ALIAS = "nightshift-convergence-20260829"


def packet_obj() -> dict[str, Any]:
    return json.loads(PINNED_PACKET.read_text(encoding="utf-8"))


def seal_obj(obj: dict[str, Any]) -> str:
    digest = nightshift_preimage_digest(obj)
    obj["packet_digest"] = f"sha256:{digest}"
    obj["switchyard"]["plan_ref"] = nightshift_plan_ref(digest)
    return canonical_json(obj)


def current_packet(
    *,
    alias: str = PINNED_ALIAS,
    created_at: datetime | None = None,
    current_until: datetime | None = None,
) -> NightshiftPacket:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    created = created_at or now - timedelta(minutes=5)
    until = current_until or now + timedelta(hours=1)
    obj = copy.deepcopy(packet_obj())
    obj["created_at"] = created.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    obj["current_until"] = until.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    obj["switchyard"]["alias"] = alias
    return packet_from_json(seal_obj(obj))
