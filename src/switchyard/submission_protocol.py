from __future__ import annotations

import copy
import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from ._vendor import rfc8785

ENVELOPE_SCHEMA = 'switchyard-envelope.v1'
SUBMISSION_RECEIPT_SCHEMA = 'switchyard-submission-receipt.v1'
NIGHTSHIFT_PACKET_SCHEMA = 'nightshift.orientation-packet/v1'
_NATIVE_MESSAGE_TYPE = 'submit'
_PLAN_REF_PREFIX = 'nightshift-packet://'
_PACKET_DIGEST_PREFIX = 'sha256:'
_NIGHTSHIFT_PACKET_DIGEST_DOMAIN_V1 = b'nightshift.orientation-packet.digest/v1\0'
_MAX_PACKET_UTF8_BYTES = 1_000_000
_MAX_ALIAS_UTF8_BYTES = 256
_MAX_PLAN_REF_UTF8_BYTES = len(_PLAN_REF_PREFIX) + 64
_MAX_NONCE_UTF8_BYTES = 36
_PLAN_REF_RE = re.compile(r'^nightshift-packet://([0-9a-f]{64})$')
_HEX_RE = re.compile(r'^[0-9a-f]{64}$')
_NIGHTSHIFT_SCHEMA_SHA256 = '6b71b4ec182811c376c4b852bc6ae540e1c063d5db43d1cacefaeead9636c50f'
_NIGHTSHIFT_SCHEMA_PATH = Path(__file__).with_name('schemas') / 'nightshift.orientation-packet.v1.schema.json'
_EXACT_WORK_PROPOSAL_SCHEMA = 'ag.governed-loop.exact-work-proposal/v1'


class SubmissionProtocolError(ValueError):
    """Raised when a plan packet, envelope, or native message is invalid."""


@dataclass(frozen=True)
class Envelope:
    alias: str
    plan_ref: str
    nonce: str

    @classmethod
    def from_obj(cls, obj: Any) -> 'Envelope':
        if not isinstance(obj, dict):
            raise SubmissionProtocolError('envelope must be a JSON object')
        schema = obj.get('schema')
        if schema is not None and schema != ENVELOPE_SCHEMA:
            raise SubmissionProtocolError(f'schema must be {ENVELOPE_SCHEMA!r} when supplied')
        allowed = {'schema', 'alias', 'plan_ref', 'nonce'}
        extra = sorted(set(obj) - allowed)
        if extra:
            raise SubmissionProtocolError(f'unexpected envelope keys: {extra}')
        alias = _required_bounded_string(obj, 'alias', max_bytes=_MAX_ALIAS_UTF8_BYTES)
        plan_ref = _required_plan_ref(_required_bounded_string(obj, 'plan_ref', max_bytes=_MAX_PLAN_REF_UTF8_BYTES))
        nonce = _required_uuid(_required_bounded_string(obj, 'nonce', max_bytes=_MAX_NONCE_UTF8_BYTES), field_name='nonce')
        return cls(alias=alias, plan_ref=plan_ref, nonce=nonce)

    def normative_obj(self) -> dict[str, str]:
        return {
            'alias': self.alias,
            'nonce': self.nonce,
            'plan_ref': self.plan_ref,
        }

    def to_obj(self, *, include_schema: bool = True) -> dict[str, str]:
        obj = dict(self.normative_obj())
        if include_schema:
            obj['schema'] = ENVELOPE_SCHEMA
        return obj

    def canonical_json(self) -> str:
        return canonical_json(self.normative_obj())

    def fingerprint(self) -> str:
        return hashlib.sha256(self.canonical_json().encode('utf-8')).hexdigest()

    def submission_text(self) -> str:
        return self.canonical_json()


@dataclass(frozen=True)
class SubmissionReceipt:
    request_id: str
    status: str
    action: str
    alias: str
    plan_ref: str
    packet_digest: str | None
    detail: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, obj: dict[str, Any]) -> 'SubmissionReceipt':
        if obj.get('schema') != SUBMISSION_RECEIPT_SCHEMA:
            raise SubmissionProtocolError(
                f'receipt schema must be {SUBMISSION_RECEIPT_SCHEMA!r}'
            )
        packet_digest = obj.get('packet_digest')
        if packet_digest is not None:
            packet_digest = _required_digest(packet_digest)
        detail = obj.get('detail', {})
        if not isinstance(detail, dict):
            raise SubmissionProtocolError('receipt detail must be an object')
        return cls(
            request_id=_required_uuid(_required_bounded_string(obj, 'request_id', max_bytes=64), field_name='request_id'),
            status=_required_bounded_string(obj, 'status', max_bytes=64),
            action=_required_bounded_string(obj, 'action', max_bytes=64),
            alias=_required_bounded_string(obj, 'alias', max_bytes=_MAX_ALIAS_UTF8_BYTES),
            plan_ref=_required_plan_ref(_required_bounded_string(obj, 'plan_ref', max_bytes=_MAX_PLAN_REF_UTF8_BYTES)),
            packet_digest=packet_digest,
            detail=detail,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            'schema': SUBMISSION_RECEIPT_SCHEMA,
            'request_id': self.request_id,
            'status': self.status,
            'action': self.action,
            'alias': self.alias,
            'plan_ref': self.plan_ref,
            'packet_digest': self.packet_digest,
            'detail': self.detail,
        }


@dataclass(frozen=True)
class NativeSubmitMessage:
    alias: str
    plan_ref: str
    nonce: str

    @classmethod
    def from_obj(cls, obj: Any) -> 'NativeSubmitMessage':
        if not isinstance(obj, dict):
            raise SubmissionProtocolError('native message must be a JSON object')
        if obj.get('type') != _NATIVE_MESSAGE_TYPE:
            raise SubmissionProtocolError('native message type must be submit')
        allowed = {'type', 'alias', 'plan_ref', 'nonce'}
        extra = sorted(set(obj) - allowed)
        if extra:
            raise SubmissionProtocolError(f'unexpected native message keys: {extra}')
        return cls(
            alias=_required_bounded_string(obj, 'alias', max_bytes=_MAX_ALIAS_UTF8_BYTES),
            plan_ref=_required_plan_ref(_required_bounded_string(obj, 'plan_ref', max_bytes=_MAX_PLAN_REF_UTF8_BYTES)),
            nonce=_required_uuid(_required_bounded_string(obj, 'nonce', max_bytes=_MAX_NONCE_UTF8_BYTES), field_name='nonce'),
        )

    def to_envelope(self) -> Envelope:
        return Envelope(alias=self.alias, plan_ref=self.plan_ref, nonce=self.nonce)


@dataclass(frozen=True)
class NightshiftPacket:
    packet_text: str
    packet_obj: dict[str, Any]
    packet_digest: str
    plan_ref: str
    alias: str
    created_at: str
    current_until: str

    @classmethod
    def from_json(cls, text: str) -> 'NightshiftPacket':
        if len(text.encode('utf-8')) > _MAX_PACKET_UTF8_BYTES:
            raise SubmissionProtocolError('packet exceeds 1 MB UTF-8 limit')
        try:
            obj = json.loads(text, object_pairs_hook=_object_without_duplicate_keys)
        except json.JSONDecodeError as exc:
            raise SubmissionProtocolError(f'invalid packet JSON: {exc}') from exc
        if not isinstance(obj, dict):
            raise SubmissionProtocolError('packet must be a JSON object')
        if text != canonical_json(obj):
            raise SubmissionProtocolError('packet bytes must be canonical RFC8785-JCS JSON')
        _validate_nightshift_schema(obj)
        _validate_nightshift_semantics(obj)

        created_at = _normalize_timestamp(obj.get('created_at'), field_name='created_at')
        current_until = _normalize_timestamp(obj.get('current_until'), field_name='current_until')
        packet_digest = obj.get('packet_digest')
        if not isinstance(packet_digest, str) or not packet_digest.startswith(_PACKET_DIGEST_PREFIX):
            raise SubmissionProtocolError('packet_digest must be sha256:<hex>')
        digest_hex = _required_digest(packet_digest[len(_PACKET_DIGEST_PREFIX):])
        recomputed_digest = nightshift_preimage_digest(obj)
        if digest_hex != recomputed_digest:
            raise SubmissionProtocolError('packet_digest does not match the Nightshift preimage')

        switchyard = obj['switchyard']
        observed_plan_ref = switchyard['plan_ref']
        expected_plan_ref = nightshift_plan_ref(digest_hex)
        if observed_plan_ref != expected_plan_ref:
            raise SubmissionProtocolError('switchyard.plan_ref does not match packet_digest')

        return cls(
            packet_text=text,
            packet_obj=obj,
            packet_digest=digest_hex,
            plan_ref=expected_plan_ref,
            alias=switchyard['alias'],
            created_at=created_at,
            current_until=current_until,
        )

    def validate_at(self, now: datetime) -> None:
        current = now.astimezone(timezone.utc)
        if current < _parse_timestamp(self.created_at) or current > _parse_timestamp(
            self.current_until
        ):
            raise SubmissionProtocolError('packet is not current')

    def is_stale(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        return current > _parse_timestamp(self.current_until)

    def canonical_preimage_json(self) -> str:
        return canonical_json(nightshift_preimage_obj(self.packet_obj))


def canonical_json(obj: Any) -> str:
    try:
        return rfc8785.dumps(obj).decode("utf-8")
    except rfc8785.CanonicalizationError as exc:
        raise SubmissionProtocolError(f"value is outside RFC8785-JCS: {exc}") from exc


def envelope_from_json(text: str) -> Envelope:
    try:
        obj = json.loads(text, object_pairs_hook=_object_without_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise SubmissionProtocolError(f'invalid envelope JSON: {exc}') from exc
    return Envelope.from_obj(obj)


def packet_from_json(text: str) -> NightshiftPacket:
    return NightshiftPacket.from_json(text)


def nightshift_preimage_obj(obj: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise SubmissionProtocolError('nightshift packet must be a JSON object')
    preimage = copy.deepcopy(obj)
    preimage.pop('packet_digest', None)
    switchyard = preimage.get('switchyard')
    if isinstance(switchyard, dict):
        switchyard.pop('plan_ref', None)
    return preimage


def nightshift_preimage_digest(obj: dict[str, Any]) -> str:
    preimage = nightshift_preimage_obj(obj)
    canonical_bytes = canonical_json(preimage).encode('utf-8')
    return hashlib.sha256(
        _NIGHTSHIFT_PACKET_DIGEST_DOMAIN_V1 + canonical_bytes
    ).hexdigest()


def nightshift_plan_ref(packet_digest: str) -> str:
    return f'{_PLAN_REF_PREFIX}{_required_digest(packet_digest)}'


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise SubmissionProtocolError(f'duplicate JSON object key: {key}')
        obj[key] = value
    return obj


def _nightshift_validator() -> Draft202012Validator:
    try:
        schema_bytes = _NIGHTSHIFT_SCHEMA_PATH.read_bytes()
    except OSError as exc:
        raise SubmissionProtocolError('vendored Nightshift packet schema is unavailable') from exc
    observed = hashlib.sha256(schema_bytes).hexdigest()
    if observed != _NIGHTSHIFT_SCHEMA_SHA256:
        raise SubmissionProtocolError('vendored Nightshift packet schema digest mismatch')
    try:
        schema = json.loads(schema_bytes)
    except json.JSONDecodeError as exc:
        raise SubmissionProtocolError('vendored Nightshift packet schema is invalid JSON') from exc
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _validate_nightshift_schema(obj: dict[str, Any]) -> None:
    errors = sorted(
        _nightshift_validator().iter_errors(obj),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        error = errors[0]
        location = '.'.join(str(part) for part in error.absolute_path) or 'packet'
        raise SubmissionProtocolError(f'Nightshift packet schema violation at {location}: {error.message}')


def _validate_nightshift_semantics(obj: dict[str, Any]) -> None:
    if obj['schema'] != NIGHTSHIFT_PACKET_SCHEMA:
        raise SubmissionProtocolError(f'schema must be {NIGHTSHIFT_PACKET_SCHEMA!r}')
    canonicalization = obj['canonicalization']
    if canonicalization != {
        'algorithm': 'RFC8785-JCS',
        'digest_algorithm': 'SHA-256',
        'digest_preimage': (
            'domain prefix nightshift.orientation-packet.digest/v1 NUL, then '
            'packet object with packet_digest and switchyard.plan_ref omitted as '
            'RFC8785-JCS'
        ),
    }:
        raise SubmissionProtocolError('packet canonicalization contract is invalid')

    created_at = _parse_timestamp(obj['created_at'])
    current_until = _parse_timestamp(obj['current_until'])
    if created_at >= current_until:
        raise SubmissionProtocolError('packet created_at must precede current_until')

    for field_name in ('agent', 'session', 'authority_basis'):
        if not obj['authoring'][field_name].strip():
            raise SubmissionProtocolError(f'authoring.{field_name} must be non-empty')
    if not obj['switchyard']['alias'].strip():
        raise SubmissionProtocolError('switchyard.alias must be non-empty')

    item_ids: set[str] = set()
    campaign_ids: set[tuple[str, str]] = set()
    graph: dict[str, list[str]] = {}
    for item in obj['work_items']:
        item_id = item['id']
        if item_id in item_ids:
            raise SubmissionProtocolError(f'duplicate work item id: {item_id}')
        item_ids.add(item_id)
        campaign_id = (item['campaign']['codename'], item['campaign']['canonical_slug'])
        if campaign_id in campaign_ids:
            raise SubmissionProtocolError('duplicate work item campaign identity')
        campaign_ids.add(campaign_id)
        graph[item_id] = item['dependencies']
        for reference in item['exact_work_refs']:
            if reference['contract_kind'] == 'exact_work_proposal_v1':
                if reference['contract_schema'] != _EXACT_WORK_PROPOSAL_SCHEMA:
                    raise SubmissionProtocolError('exact-work proposal schema is invalid')
            elif not reference['contract_schema'].strip():
                raise SubmissionProtocolError('repository actual contract schema is empty')

    for dependencies in graph.values():
        for dependency in dependencies:
            if dependency not in item_ids:
                raise SubmissionProtocolError(f'unknown work item dependency: {dependency}')

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(item_id: str) -> None:
        if item_id in visited:
            return
        if item_id in visiting:
            raise SubmissionProtocolError('work item dependency graph contains a cycle')
        visiting.add(item_id)
        for dependency in graph[item_id]:
            visit(dependency)
        visiting.remove(item_id)
        visited.add(item_id)

    for item_id in graph:
        visit(item_id)


def _required_bounded_string(obj: dict[str, Any], key: str, *, max_bytes: int) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise SubmissionProtocolError(f'{key} must be a non-empty string')
    if len(value.encode('utf-8')) > max_bytes:
        raise SubmissionProtocolError(f'{key} exceeds {max_bytes} UTF-8 bytes')
    return value


def _required_uuid(value: str, *, field_name: str) -> str:
    try:
        return str(uuid.UUID(value))
    except ValueError as exc:
        raise SubmissionProtocolError(f'{field_name} must be a UUID') from exc


def _required_digest(value: str) -> str:
    lowered = value.lower()
    if not _HEX_RE.fullmatch(lowered):
        raise SubmissionProtocolError('packet_digest must be a 64-character hexadecimal SHA256')
    return lowered


def _required_plan_ref(value: str) -> str:
    match = _PLAN_REF_RE.fullmatch(value)
    if not match:
        raise SubmissionProtocolError('plan_ref must be nightshift-packet://<64 lowercase hex>')
    return value


def _normalize_timestamp(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise SubmissionProtocolError(f'{field_name} must be an RFC3339 timestamp string')
    return _render_timestamp(_parse_timestamp(value))


def _parse_timestamp(value: str) -> datetime:
    text = value.replace('Z', '+00:00')
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise SubmissionProtocolError('timestamps must use RFC3339/ISO-8601 syntax') from exc
    if parsed.tzinfo is None:
        raise SubmissionProtocolError('timestamps must include a timezone offset')
    return parsed.astimezone(timezone.utc)


def _render_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
