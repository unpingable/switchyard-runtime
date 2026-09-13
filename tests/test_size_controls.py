"""Synthetic size controls: no provider/model contact or campaign material."""
import copy
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator

from switchyard.appserver import (AcquisitionCut, AcquisitionEnvelope, AppServerClient,
    AppServerError, ServerMessage, request_wire)
from switchyard.provider_admission import (ProviderAdmissionMapper, ProviderAdmissionError,
    FINAL_CODEX_SOURCE_HEAD, replay_snapshot, seal_binding)
from switchyard.provider_runner import _canonical, digest

ROOT = Path(__file__).resolve().parents[1]


def synthetic_snapshot(wire_size=118500):
    """Full-shape evidence fixture, not testimony of a real provider execution."""
    mapper = ProviderAdmissionMapper(seal_binding({
        'work_attempt_id': 'beta-fixture-attempt', 'dispatch_occurrence_id': 'beta-fixture-dispatch',
        'adapter_process_occurrence_id': 'beta-fixture-process', 'app_server_session_identity': 'beta-fixture-estate',
        'thread_id': 'synthetic-thread', 'turn_id': 'synthetic-turn', 'provider': 'openai', 'model': 'gpt-5.6-terra',
        'codex_source_head': FINAL_CODEX_SOURCE_HEAD, 'executable_kind': 'DETERMINISTIC_FIXTURE',
        'app_server_executable_identity': 'synthetic-size-fixture-not-a-provider',
        'app_server_executable_sha256': 'sha256:' + 'a' * 64, 'internal_provider_request_retries': 0}),
        capture_contract='BOUNDED_TURN_V1')
    params = {'threadId': 'synthetic-thread', 'model': 'gpt-5.6-terra',
        'input': [{'type': 'text', 'text': ''}]}
    outbound = {'id': 3, 'method': 'turn/start', 'params': params}
    if wire_size is not None:
        params['input'][0]['text'] = 'S' * (wire_size - len(request_wire(outbound)))
        assert len(request_wire(outbound)) == wire_size
    mapper.consume_envelope(AcquisitionEnvelope(0, 'CLIENT_REQUEST',
        ServerMessage(outbound, request_wire(outbound)), request_method='turn/start'))
    response = {'id': 3, 'result': {'turn': {'id': 'synthetic-turn'}}}
    mapper.consume_envelope(AcquisitionEnvelope(1, 'CLIENT_RESPONSE',
        ServerMessage(response, request_wire(response)), request_method='turn/start'))
    common = {'threadId': 'synthetic-thread', 'turnId': 'synthetic-turn',
        'requestOccurrenceId': 'synthetic-request', 'samplingOrdinal': 0, 'requestOrder': 0,
        'provider': 'openai', 'model': 'gpt-5.6-terra'}
    frames = [('providerRequest/started', {**common, 'startedAtMs': 1788177660100}),
        ('rawResponse/started', {**common, 'responseId': 'synthetic-response', 'observedAtMs': 1788177660101}),
        ('rawResponse/completed', {'threadId': 'synthetic-thread', 'turnId': 'synthetic-turn',
            'responseId': 'synthetic-response', 'usage': None}),
        ('item/completed', {'threadId': 'synthetic-thread', 'turnId': 'synthetic-turn',
            'item': {'type': 'agentMessage', 'text': 'SYNTHETIC_NO_PROVIDER_CONTACT'}}),
        ('turn/completed', {'threadId': 'synthetic-thread', 'turn': {'id': 'synthetic-turn', 'status': 'completed'}})]
    for ordinal, (method, values) in enumerate(frames, 2):
        obj = {'method': method, 'params': values}
        mapper.consume_envelope(AcquisitionEnvelope(ordinal, 'NOTIFICATION', ServerMessage(obj, request_wire(obj))))
    mapper.consume_cut(AcquisitionCut(True, 0, 'EXITED', len(frames) + 2, 'beta-fixture-process', 'beta-fixture-estate'))
    return mapper.snapshot()


def client(pipe=None, queue_bytes=16 * 1024 * 1024):
    value = AppServerClient(['not-launched'], enable_ordered_acquisition=True,
        capture_contract='BOUNDED_TURN_V1',
        adapter_process_occurrence_id='synthetic-process', app_server_session_identity='synthetic-estate',
        maximum_ordered_queue_bytes=queue_bytes)
    value._proc = SimpleNamespace(stdin=pipe if pipe is not None else io.BytesIO())
    return value


def test_full_shape_request_wire_is_sent_and_retained_exactly():
    snapshot = synthetic_snapshot()
    record = snapshot['records'][0]
    wire = bytes.fromhex(record['raw']['bytes_hex'])
    assert len(wire) == 118500
    candidate = client()
    candidate._write(json.loads(wire), acquisition_kind='CLIENT_REQUEST', request_method='turn/start')
    assert candidate._proc.stdin.getvalue() == wire
    assert candidate.drain_ordered_acquisition()[0].message.raw_bytes == wire
    assert replay_snapshot(snapshot, capture_contract='BOUNDED_TURN_V1').snapshot() == snapshot
    schema = json.loads((ROOT / 'src/switchyard/schemas/switchyard.codex-provider-admission.bounded-turn.v1.schema.json').read_bytes())
    Draft202012Validator(schema).validate(snapshot)
    old_schema = json.loads((ROOT / 'src/switchyard/schemas/switchyard.codex-provider-admission.beta-final.v1.schema.json').read_bytes())
    assert not Draft202012Validator(old_schema).is_valid(snapshot)


@pytest.mark.parametrize('method,size', [('turn/start', 262145), ('thread/start', 16385), ('unknown/method', 16385)])
def test_oversize_or_unselected_request_refuses_before_send(method, size):
    candidate = client()
    request = {'id': 1, 'method': method, 'params': {'text': ''}}
    request['params']['text'] = 'S' * (size - len(request_wire(request)))
    with pytest.raises(AppServerError, match='pre-send'):
        candidate._write(request, acquisition_kind='CLIENT_REQUEST', request_method=method)
    assert candidate._proc.stdin.getvalue() == b''
    assert candidate.drain_ordered_acquisition() == []


def test_queue_refusal_precedes_send():
    candidate = client(queue_bytes=128)
    with pytest.raises(AppServerError, match='queue refused before send'):
        candidate._write({'id': 1, 'method': 'turn/start', 'params': {'text': 'S' * 128}},
            acquisition_kind='CLIENT_REQUEST', request_method='turn/start')
    assert candidate._proc.stdin.getvalue() == b''


def test_short_writes_preserve_entire_preflighted_wire():
    class ShortPipe(io.BytesIO):
        def write(self, data):
            return super().write(data[:97])
    candidate = client(ShortPipe())
    request = {'id': 1, 'method': 'turn/start', 'params': {'text': 'S' * 100000}}
    candidate._write(request, acquisition_kind='CLIENT_REQUEST', request_method='turn/start')
    assert candidate._proc.stdin.getvalue() == request_wire(request)


def test_response_loss_does_not_repeat_the_sent_request():
    candidate = client(); candidate.request_timeout = 0.01
    params = {'text': 'S' * 100000}
    with pytest.raises(AppServerError, match='timeout waiting'):
        candidate.request('turn/start', params)
    expected = request_wire({'id': 1, 'method': 'turn/start', 'params': params})
    assert candidate._proc.stdin.getvalue() == expected
    records = candidate.drain_ordered_acquisition()
    assert len(records) == 1 and records[0].message.raw_bytes == expected


def test_partial_write_failure_never_restarts_the_wire():
    class FailingPipe(io.BytesIO):
        def write(self, data):
            if self.tell():
                raise OSError('synthetic pipe closed after partial write')
            return super().write(data[:97])
    candidate = client(FailingPipe())
    request = {'id': 1, 'method': 'turn/start', 'params': {'text': 'S' * 100000}}
    with pytest.raises(OSError, match='synthetic pipe'):
        candidate._write(request, acquisition_kind='CLIENT_REQUEST', request_method='turn/start')
    assert candidate._proc.stdin.getvalue() == request_wire(request)[:97]
    assert len(candidate.drain_ordered_acquisition()) == 1


def test_large_request_without_response_cannot_acquire_clean_cut():
    snapshot = synthetic_snapshot()
    mapper = ProviderAdmissionMapper(snapshot['binding'], capture_contract='BOUNDED_TURN_V1')
    wire = bytes.fromhex(snapshot['records'][0]['raw']['bytes_hex'])
    mapper.consume_envelope(AcquisitionEnvelope(0, 'CLIENT_REQUEST', ServerMessage(json.loads(wire), wire), request_method='turn/start'))
    mapper.consume_cut(AcquisitionCut(True, 0, 'EXITED', 1, 'beta-fixture-process', 'beta-fixture-estate'))
    retained = mapper.snapshot()
    assert retained['acquisition_cut']['clean'] is False
    assert retained['admission_disposition'] == 'ADMISSION_INDETERMINATE'
    assert replay_snapshot(retained, capture_contract='BOUNDED_TURN_V1').snapshot() == retained


def test_other_evidence_lanes_retain_original_bound():
    snapshot = synthetic_snapshot()
    wire = bytes.fromhex(snapshot['records'][0]['raw']['bytes_hex'])
    mapper = ProviderAdmissionMapper(snapshot['binding'], capture_contract='BOUNDED_TURN_V1')
    with pytest.raises(ProviderAdmissionError, match='byte bound'):
        mapper.consume_envelope(AcquisitionEnvelope(0, 'CLIENT_RESPONSE', ServerMessage(json.loads(wire), wire), request_method='turn/start'))
    assert mapper.records == []


def test_capture_context_is_explicit_closed_and_defaults_to_legacy():
    snapshot = synthetic_snapshot()
    with pytest.raises(ProviderAdmissionError, match='byte bound'):
        replay_snapshot(snapshot)
    mapper = ProviderAdmissionMapper(snapshot['binding'])
    wire = bytes.fromhex(snapshot['records'][0]['raw']['bytes_hex'])
    with pytest.raises(ProviderAdmissionError, match='byte bound'):
        mapper.consume_envelope(AcquisitionEnvelope(0, 'CLIENT_REQUEST', ServerMessage(json.loads(wire), wire), request_method='turn/start'))
    for selector in ['unknown', '', 262144, None]:
        with pytest.raises(ValueError, match='unknown provider capture'):
            ProviderAdmissionMapper(snapshot['binding'], capture_contract=selector)
        with pytest.raises(ValueError, match='unknown provider capture'):
            replay_snapshot(snapshot, capture_contract=selector)
        with pytest.raises(ValueError, match='unknown provider capture'):
            AppServerClient(['not-launched'], capture_contract=selector)
    old = AppServerClient(['not-launched'], enable_ordered_acquisition=True,
        adapter_process_occurrence_id='synthetic-process', app_server_session_identity='synthetic-estate')
    old._proc = SimpleNamespace(stdin=io.BytesIO())
    with pytest.raises(AppServerError, match='pre-send'):
        old._write(json.loads(wire), acquisition_kind='CLIENT_REQUEST', request_method='turn/start')
    assert old._proc.stdin.getvalue() == b''


def test_compact_cross_language_fixture_matches_source():
    retained = json.loads((ROOT / 'tests/fixtures/bounded-turn-synthetic.json').read_bytes())
    assert retained['qualification'] == 'SYNTHETIC_NO_PROVIDER_CONTACT'
    assert retained['compact_snapshot'] == synthetic_snapshot(None)
    snapshot = synthetic_snapshot(retained['wire_size'])
    assert snapshot['snapshot_digest'] == retained['expanded_snapshot_digest']


@pytest.mark.skipif(not (ROOT / 'tests/test_provider_runner.py').exists(), reason='canonical runner fixture')
def test_runner_preflight_before_capture_or_claim(tmp_path, monkeypatch):
    from switchyard import provider_runner as runner
    from test_provider_runner import inputs, dispatch_for
    request, brief, backend = inputs(tmp_path)
    # Standalone canonical request-shape checking is covered elsewhere. This
    # boundary case isolates the pre-backend check with an oversized byte input.
    monkeypatch.setattr(runner, 'validate_request', lambda *_: None)
    monkeypatch.setattr(runner, 'validate_dispatch', lambda *_: None)
    monkeypatch.setattr(runner, 'verify_backend', lambda *_: pytest.fail('backend capture reached'))
    store = SimpleNamespace(lookup=lambda *_: None, claim=lambda *_: pytest.fail('claim reached'))
    with pytest.raises(Exception, match='before backend start'):
        runner.run(request, b'S' * 300000, backend, store, dispatch_record=dispatch_for(request, backend))


@pytest.mark.skipif(not (ROOT / 'tests/test_provider_runner.py').exists(), reason='canonical runner fixture')
def test_native_preflight_has_no_state_surface_and_preserves_inputs(tmp_path):
    import subprocess
    import sys
    from test_provider_runner import inputs
    request, brief, backend = inputs(tmp_path)
    for name, raw in [('request', _canonical(request)), ('brief', brief), ('backend', _canonical(backend))]:
        (tmp_path / (name + '.json')).write_bytes(raw)
    args = [sys.executable, '-m', 'switchyard.provider_runner', 'preflight-request']
    for name in ['request', 'brief', 'backend']:
        args.extend(['--' + name, str(tmp_path / (name + '.json'))])
    before = {p.name: p.read_bytes() for p in tmp_path.glob('*.json')}
    result = subprocess.run(args, capture_output=True, check=True)
    report = json.loads(result.stdout)
    assert report['maximum_turn_start_wire_bytes'] == 262144
    assert report['provider_contact'] is False
    assert {p.name: p.read_bytes() for p in tmp_path.glob('*.json')} == before
    assert not list(tmp_path.glob('*.sqlite'))
    # An older accepted schema remains capped at 16KiB on the new runner.
    from switchyard.provider_runner import V3_DOMAIN
    request['switchyard_schema_sha256'] = 'sha256:0e9c851cc9fad9538408ab44d84737d5f4d4d7ef39f2fd5db20c6f88fc7fbb9e'
    request['request_digest'] = digest(V3_DOMAIN + _canonical({k: v for k, v in request.items() if k != 'request_digest'}))
    (tmp_path / 'request.json').write_bytes(_canonical(request))
    refusal = subprocess.run(args, capture_output=True)
    assert refusal.returncode != 0 and b'before backend start' in refusal.stderr
    assert not list(tmp_path.glob('*.sqlite'))
