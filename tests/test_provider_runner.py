import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from switchyard.appserver import AcquisitionCut, AcquisitionEnvelope, ServerMessage
from switchyard.nightshift_adapter import _canonical, _digest, START_DOMAIN
from switchyard.provider_admission import FINAL_CODEX_SOURCE_HEAD as CODEX_SOURCE_HEAD
from switchyard.provider_runner import BOUNDED_BASE_INSTRUCTIONS, BOUNDED_DEVELOPER_INSTRUCTIONS, PROVENANCE_SCHEMA, RUNNER_SOURCE_CLOSURE, RunStore, bounded_thread_start, digest, inspect, load_at, preflight_request, reconcile, run as actual_run, validate_request, verify_backend, verify_runner_provenance, V3_DOMAIN, DISPATCH_DOMAIN
from test_nightshift_adapter import build_request_brief


def dispatch_for(request, backend):
    dispatch = {key:request[key] for key in ("packet_digest", "run_id", "work_item_id", "work_attempt_id", "dispatch_occurrence_id",
        "selected_model_ordinal", "adapter_id", "adapter_version", "adapter_protocol", "worker_brief_digest",
        "internal_provider_retry_count", "provider_execution_id", "authority_effect")}
    dispatch.update(schema="nightshift.provider-dispatch-occurrence/v1", requirement_digest="sha256:"+'a'*64,
        policy_digest="sha256:"+'b'*64, dispatch_ordinal=1,
        selection={key:request[key] for key in ("provider_id", "model_id", "model_class")},
        adapter_process_occurrence_id="fixture-admitted-process", app_server_session_identity=digest(str(Path(backend['codex_home']).resolve()).encode()),
        worker_start_request_schema=request['schema'], worker_start_request_digest=request['request_digest'], opened_at="2026-09-08T12:00:00Z")
    dispatch['dispatch_digest'] = digest(DISPATCH_DOMAIN + _canonical(dispatch))
    return dispatch


def run(request, brief, backend, store, **kwargs):
    return actual_run(request, brief, backend, store, dispatch_record=dispatch_for(request, backend), **kwargs)


def inputs(tmp_path):
    v2, brief, _ = build_request_brief(tmp_path)
    v2['adapter_protocol'] = 'switchyard.codex-app-server/v2'
    v2['adapter_version'] = '2.0.0'
    v2['request_digest'] = _digest(START_DOMAIN, {k:v for k,v in v2.items() if k != 'request_digest'})
    raw = _canonical(v2)
    request = {**v2, 'schema':'nightshift.worker-start-request/v3',
        'predecessor_schema':v2['schema'], 'predecessor_request_digest':v2['request_digest'],
        'predecessor_sha256':digest(raw), 'predecessor_encoding':'hex', 'predecessor_bytes_hex':raw.hex(),
        'profile_digest':'sha256:'+'a'*64, 'work_attempt_id':v2['attempt_id'], 'dispatch_occurrence_id':'dispatch-test',
        'provider_id':'openai', 'model_id':'gpt-5.6-terra', 'model_class':'large-model', 'selected_model_ordinal':0,
        'provider_admission_adapter_protocol':'switchyard.codex-app-server/v2',
        'provider_admission_binding_schema':'switchyard.codex-provider-admission-binding/v1',
        'provider_admission_evidence_schema':'switchyard.codex-provider-admission-evidence/v1',
        'provider_admission_snapshot_schema':'switchyard.codex-provider-admission-snapshot/v1',
        'codex_owner_head':CODEX_SOURCE_HEAD, 'switchyard_owner_head':'2ba25db66d8b29dd215bd87e05f4ea794024b3b7',
        'switchyard_schema_sha256':digest((Path(__file__).parents[1]/'src/switchyard/schemas/switchyard.codex-provider-admission.bounded-turn.v1.schema.json').read_bytes()),
        'switchyard_deterministic_fixture_sha256':'sha256:cafa673ac58f60029fd6c1de229b4f57d9f42ba918b7ecb2a3bfb20cb2b41a31',
        'provider_execution_id':None,'internal_provider_retry_count':0,'semantic_retry':False,
        'approval_response_authorized':False,'authority_effect':'LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY'}
    request['request_digest'] = digest(V3_DOMAIN+_canonical({k:v for k,v in request.items() if k!='request_digest'}))
    home = tmp_path/'profile'; home.mkdir()
    binary = Path('/usr/bin/true')
    backend = {'schema':'switchyard.provider-backend/v1','executable':str(binary),
        'executable_sha256':digest(binary.read_bytes()),'executable_shape':'standalone-app-server',
        'codex_source_head':CODEX_SOURCE_HEAD,'codex_home':str(home),'provider':'openai','model':'gpt-5.6-terra'}
    return request, brief, backend


def test_all_final_schema_forms_match_v3_enum_and_echo_preflights_without_transport(tmp_path):
    request, brief, backend = inputs(tmp_path)
    schemas = Path(__file__).parents[1] / 'src/switchyard/schemas'
    names = (
        'switchyard.codex-provider-admission.beta-final.v1.schema.json',
        'switchyard.codex-provider-admission.bounded-turn.v1.schema.json',
        'switchyard.codex-provider-admission.bounded-turn-echo.v2.schema.json',
    )
    worker = json.loads((schemas / 'nightshift.worker-start-request.v3.schema.json').read_text())
    allowed = set(worker['properties']['switchyard_schema_sha256']['enum'])
    expected = {digest((schemas / name).read_bytes()) for name in names}
    assert expected <= allowed

    echo_digest = digest((schemas / names[-1]).read_bytes())
    assert echo_digest == 'sha256:c851fb5dd157ebb70896da06db50a07b968b3c0d357b2defc73ca267b9d82f93'
    assert 'sha256:2bcf795c753a08d3c7e2ef8b521b44b155054fccbd50452662230d59ddd3f293' in allowed
    request['switchyard_schema_sha256'] = echo_digest
    request['request_digest'] = digest(V3_DOMAIN + _canonical({k: v for k, v in request.items() if k != 'request_digest'}))
    before = list(Client.calls)
    result = preflight_request(request, brief, backend)
    assert result['provider_contact'] is False
    assert Client.calls == before


def test_unsupported_schema_digest_refuses_preflight_without_transport(tmp_path):
    request, brief, backend = inputs(tmp_path)
    request['switchyard_schema_sha256'] = 'sha256:' + 'f' * 64
    request['request_digest'] = digest(V3_DOMAIN + _canonical({k: v for k, v in request.items() if k != 'request_digest'}))
    before = list(Client.calls)
    with pytest.raises(Exception):
        preflight_request(request, brief, backend)
    assert Client.calls == before


def test_retired_echo_digest_remains_schema_valid_but_cannot_start_new_execution(tmp_path):
    request, brief, backend = inputs(tmp_path)
    request['switchyard_schema_sha256'] = 'sha256:2bcf795c753a08d3c7e2ef8b521b44b155054fccbd50452662230d59ddd3f293'
    request['request_digest'] = digest(V3_DOMAIN + _canonical(
        {k: v for k, v in request.items() if k != 'request_digest'}))
    before = list(Client.calls)
    with pytest.raises(Exception, match='request owner/schema tuple differs'):
        preflight_request(request, brief, backend)
    assert Client.calls == before


def runner_provenance(tmp_path, request):
    root = Path(__file__).parents[1]
    files = {}
    for relative in RUNNER_SOURCE_CLOSURE:
        raw = (root / relative).read_bytes()
        files[relative] = {"canonical_path": relative, "bytes": len(raw),
                           "sha256": hashlib.sha256(raw).hexdigest()}
    value = {"schema": PROVENANCE_SCHEMA, "canonical_source": "Switchyard",
             "canonical_revision": request["switchyard_owner_head"],
             "export_procedure": "tools/export-runtime.mjs", "authored_material_license": "Apache-2.0",
             "third_party_notices_retained": True, "files": files}
    path = tmp_path / "SOURCE-PROVENANCE.json"
    path.write_text(json.dumps(value, sort_keys=True))
    return path, value


def checked_source_revision():
    return subprocess.run(["git", "-C", str(Path(__file__).parents[1]), "rev-parse", "HEAD"],
                          check=True, capture_output=True, text=True).stdout.strip()


class Client:
    calls = []
    request_params = []
    mode = 'completed'
    def __init__(self, command, **kwargs):
        self.events = []; self.ordinal = 0; self.kwargs = kwargs
    def event(self, method, params):
        obj={'method':method,'params':params}
        self.events.append(AcquisitionEnvelope(self.ordinal,'NOTIFICATION',ServerMessage(obj,_canonical(obj)+b'\n')))
        self.ordinal += 1
    def start(self):
        self.calls.append('initialize')
    def request(self, method, params):
        self.calls.append(method)
        self.request_params.append((method, copy.deepcopy(params)))
        if method == 'thread/start': return {'thread':{'id':'thread-test'}, 'model':'gpt-5.6-terra',
            'modelProvider':'openai', 'cwd':params['cwd'], 'runtimeWorkspaceRoots':params['runtimeWorkspaceRoots'],
            'instructionSources':[], 'activePermissionProfile':{'id':'provider-bounded-read','extends':None}}
        if method == 'thread/read': return {'thread':{'id':'thread-test','turns':[{'id':'turn-test','status':'completed'}]}}
        if method == 'turn/start':
            common={'threadId':'thread-test','turnId':'turn-test','requestOccurrenceId':'request-test',
                'samplingOrdinal':0,'requestOrder':0,'provider':'openai','model':'gpt-5.6-terra'}
            self.event('providerRequest/started',{**common,'startedAtMs':100})
            self.event('rawResponse/started',{**common,'responseId':'response-test','observedAtMs':101})
            self.event('rawResponse/completed',{'threadId':'thread-test','turnId':'turn-test','responseId':'response-test','usage':None})
            if self.mode == 'approval':
                obj={'id':90,'method':'item/commandExecution/requestApproval','params':{'threadId':'thread-test','turnId':'turn-test'}}
                self.events.append(AcquisitionEnvelope(self.ordinal,'SERVER_REQUEST',ServerMessage(obj,_canonical(obj)+b'\n')));self.ordinal+=1
            elif self.mode != 'loss':
                self.event('item/completed',{'threadId':'thread-test','turnId':'turn-test','item':{'type':'agentMessage','text':'bounded finding'}})
                self.event('thread/tokenUsage/updated',{'threadId':'thread-test','turnId':'turn-test','tokenUsage':{'total':{'inputTokens':10,'outputTokens':3}}})
                self.event('turn/completed',{'threadId':'thread-test','turn':{'id':'turn-test','status':self.mode}})
            else:
                self.events.append(AcquisitionEnvelope(self.ordinal,'LOSS',diagnostic='fixture transport loss'));self.ordinal+=1
            return {'turn':{'id':'turn-test'}}
        raise AssertionError(method)
    def drain_ordered_acquisition(self):
        events=self.events; self.events=[]; return events
    def quiesce_acquisition(self, timeout=5):
        return AcquisitionCut(True,0,'EXITED',self.ordinal,self.kwargs.get('adapter_process_occurrence_id'),self.kwargs.get('app_server_session_identity'))


def test_runner_provenance_binds_current_source_closure_and_refuses_mismatch(tmp_path):
    request, _brief, _backend = inputs(tmp_path)
    request["switchyard_owner_head"] = checked_source_revision()
    request["request_digest"] = digest(V3_DOMAIN + _canonical({k: v for k, v in request.items() if k != "request_digest"}))
    path, value = runner_provenance(tmp_path, request)
    verify_runner_provenance(path, request)
    value["schema"] = "wrong/v1"
    path.write_text(json.dumps(value, sort_keys=True))
    with pytest.raises(Exception, match="schema"):
        verify_runner_provenance(path, request)
    value["schema"] = PROVENANCE_SCHEMA
    path.write_text(json.dumps(value, sort_keys=True))
    wrong_head = {**request, "switchyard_owner_head": "0" * 40}
    with pytest.raises(Exception, match="revision"):
        verify_runner_provenance(path, wrong_head)
    value["files"]["src/switchyard/provider_runner.py"]["sha256"] = "0" * 64
    path.write_text(json.dumps(value, sort_keys=True))
    with pytest.raises(Exception, match="installed runner source"):
        verify_runner_provenance(path, request)


def test_runner_provenance_under_held_root_requires_relative_record(tmp_path):
    request, _brief, _backend = inputs(tmp_path)
    request["switchyard_owner_head"] = checked_source_revision()
    request["request_digest"] = digest(V3_DOMAIN + _canonical({k: v for k, v in request.items() if k != "request_digest"}))
    held_root = tmp_path / "held-root"
    held_root.mkdir()
    path, _value = runner_provenance(held_root, request)
    root_fd = os.open(held_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        verify_runner_provenance(path.name, request, root_fd=root_fd)
        with pytest.raises(Exception):
            verify_runner_provenance(str(path), request, root_fd=root_fd)
        with pytest.raises(Exception):
            verify_runner_provenance("../SOURCE-PROVENANCE.json", request, root_fd=root_fd)
    finally:
        os.close(root_fd)


def test_runner_uses_verified_provenance_before_component_dispatch(tmp_path):
    request, brief, backend = inputs(tmp_path)
    request["switchyard_owner_head"] = checked_source_revision()
    request["request_digest"] = digest(V3_DOMAIN + _canonical({k: v for k, v in request.items() if k != "request_digest"}))
    path, _value = runner_provenance(tmp_path, request)
    Client.calls = []; Client.request_params = []; Client.mode = "completed"
    result = run(request, brief, backend, RunStore(tmp_path / "adapter.sqlite"),
                 source_provenance=path, client_factory=Client)
    assert result["state"] == "PROVIDER_COMPLETED"


def test_complete_and_duplicate_never_redispatch(tmp_path):
    request,brief,backend=inputs(tmp_path)
    Client.calls=[]; Client.request_params=[]; Client.mode='completed'
    store=RunStore(tmp_path/'adapter.sqlite')
    result=run(request,brief,backend,store,client_factory=Client)
    assert result['state']=='PROVIDER_COMPLETED'
    assert result['worker_output']=='bounded finding'
    assert result['usage_state']=='OBSERVED'
    assert result['usage_scope']=='THREAD_CUMULATIVE_AND_LAST_PROVIDER_USAGE'
    assert result['usage_turn_id']=='turn-test'
    assert result['requested_execution']=={
        'provider_id':'openai','model_id':'gpt-5.6-terra',
        'request_digest':request['request_digest'],
        'work_attempt_id':request['work_attempt_id'],
        'dispatch_occurrence_id':request['dispatch_occurrence_id']}
    assert result['observed_execution']=={
        'state':'OBSERVED_PROVIDER_BOUNDARY','provider_id':'openai',
        'model_id':'gpt-5.6-terra','source':'ORDERED_PROVIDER_ADMISSION_EVIDENCE'}
    assert result['cost'] is None
    assert result['cost_state']=='NOT_OBSERVABLE'
    assert result['cost_scope']=='NOT_OBSERVABLE'
    assert result['acceptance_state']=='NOT_EVALUATED_BY_SWITCHYARD'
    assert run(request,brief,backend,store,client_factory=Client)==result
    assert Client.calls==['initialize','thread/start','turn/start']
    assert inspect(tmp_path/'adapter.sqlite',request['dispatch_occurrence_id'])==result


def test_thread_context_is_closed_to_read_only_workspace(tmp_path):
    request, brief, backend = inputs(tmp_path)
    workspace = Path(request['workspace_identity'])
    params = bounded_thread_start(workspace, backend)
    assert params == {
        'cwd':str(workspace), 'experimentalRawEvents':True, 'runtimeWorkspaceRoots':[],
        'model':'gpt-5.6-terra', 'modelProvider':'openai',
        'allowProviderModelFallback':False, 'approvalPolicy':'untrusted',
        'permissions':'provider-bounded-read',
        'config':{
            'permissions':{'provider-bounded-read':{'filesystem':{
                ':minimal':'read', str(workspace):'read',
                str(Path(backend['executable']).resolve(strict=True)):'read'},
                'network':{'enabled':False}}},
            'project_doc_max_bytes':0,
            'include_permissions_instructions':False,
            'include_apps_instructions':False,
            'shell_environment_policy':{
                'inherit':'none', 'ignore_default_excludes':False,
                'set':{'PATH':'/usr/bin:/bin', 'LANG':'C.UTF-8'}},
            'analytics.enabled':False, 'check_for_update_on_startup':False,
            'agents.enabled':False,
            'features.multi_agent':False, 'features.multi_agent_v2':False,
            'features.apps':False, 'features.enable_mcp_apps':False,
            'features.plugins':False, 'features.recommended_plugins':False,
            'features.executor_capability_discovery':False,
            'features.skip_host_skill_discovery':True,
            'features.hooks':False,
            'features.standalone_web_search':False,
            'features.web_search_request':False, 'features.web_search_cached':False,
            'features.view_image':False, 'features.memory_tool':False,
            'features.external_agent_memory_import':False,
            'features.unbounded_connection_retries':False},
        'baseInstructions':BOUNDED_BASE_INSTRUCTIONS,
        'developerInstructions':BOUNDED_DEVELOPER_INSTRUCTIONS,
        'dynamicTools':[], 'selectedCapabilityRoots':[], 'environments':[], 'ephemeral':True}
    Client.calls=[]; Client.request_params=[]; Client.mode='completed'
    run(request, brief, backend, RunStore(tmp_path/'adapter.sqlite'), client_factory=Client)
    assert Client.request_params[0] == ('thread/start', params)


def test_thread_context_admits_only_exact_backend_executable_not_parent(tmp_path):
    request, _, backend = inputs(tmp_path)
    workspace = Path(request['workspace_identity'])
    executable = Path(backend['executable']).resolve(strict=True)
    filesystem = bounded_thread_start(workspace, backend)['config']['permissions'][
        'provider-bounded-read']['filesystem']
    assert filesystem[executable.as_posix()] == 'read'
    assert executable.parent.as_posix() not in filesystem
    assert '/data' not in filesystem
    assert '/data/git' not in filesystem
    assert set(filesystem) == {':minimal', str(workspace), executable.as_posix()}


@pytest.mark.parametrize('field,value', [
    ('instructionSources',['/data/git/AGENTS.md']),
    ('runtimeWorkspaceRoots',['/data/git']),
    ('activePermissionProfile',{'id':':read-only','extends':None}),
    ('model','gpt-5.6-sol'),
    ('modelProvider',None),
    ('cwd',None),
])
def test_effective_thread_context_disagreement_refuses_before_turn(tmp_path, field, value):
    class DifferentContextClient(Client):
        def request(self, method, params):
            result = super().request(method, params)
            if method == 'thread/start': result[field] = value
            return result
    request, brief, backend = inputs(tmp_path)
    Client.calls=[]; Client.request_params=[]; Client.mode='completed'
    result = run(request, brief, backend, RunStore(tmp_path/'adapter.sqlite'), client_factory=DifferentContextClient)
    assert result['state'] == 'OUTCOME_UNKNOWN'
    assert result['thread_id'] is None
    assert Client.calls == ['initialize','thread/start']


@pytest.mark.parametrize('method', ['item/completed', 'thread/tokenUsage/updated'])
@pytest.mark.parametrize('other_turn', ['different-turn', None])
def test_output_and_usage_require_exact_turn(tmp_path, method, other_turn):
    class ForeignTurnClient(Client):
        mode = 'completed'
        def event(self, event_method, params):
            if event_method == method:
                params = {**params, 'turnId': other_turn}
                if other_turn is None:
                    params.pop('turnId')
            super().event(event_method, params)
    request, brief, backend = inputs(tmp_path)
    result = run(request, brief, backend, RunStore(tmp_path/'adapter.sqlite'), client_factory=ForeignTurnClient)
    assert result['state'] == 'OUTCOME_UNKNOWN'
    assert result['worker_output'] is None
    assert result['usage'] is None
    assert result['usage_scope'] == 'NOT_OBSERVABLE'


@pytest.mark.parametrize('mode,expected',[('failed','PROVIDER_FAILED'),('interrupted','PROVIDER_INTERRUPTED'),('loss','OUTCOME_UNKNOWN'),('approval','OUTCOME_UNKNOWN')])
def test_non_success_is_distinct_and_no_approval_response(tmp_path,mode,expected):
    request,brief,backend=inputs(tmp_path); Client.calls=[];Client.mode=mode
    result=run(request,brief,backend,RunStore(tmp_path/'adapter.sqlite'),client_factory=Client)
    assert result['state']==expected
    assert result['approval_response_sent'] is False
    assert Client.calls==['initialize','thread/start','turn/start']


def test_claim_before_contact_survives_restart(tmp_path):
    request,brief,backend=inputs(tmp_path);Client.calls=[]
    path=tmp_path/'adapter.sqlite'; store=RunStore(path)
    record,new=store.claim(request,brief,backend,dispatch_for(request,backend));assert new
    store.db.close()
    result=run(request,brief,backend,RunStore(path),client_factory=Client)
    assert result['state']=='OUTCOME_UNKNOWN'
    assert result['observed_execution']['state']=='NOT_OBSERVABLE'
    assert result['acceptance_state']=='NOT_EVALUATED_BY_SWITCHYARD'
    assert not Client.calls


def test_substitution_and_no_fallback(tmp_path):
    request,brief,backend=inputs(tmp_path)
    validate_request(request,brief)
    bad=copy.deepcopy(request);bad['model_id']='gpt-5.6-sol'
    with pytest.raises(Exception):validate_request(bad,brief)
    with pytest.raises(Exception):run(request,brief,{**backend,'model':'gpt-5.6-sol'},RunStore(tmp_path/'adapter.sqlite'),client_factory=Client)
    store=RunStore(tmp_path/'adapter.sqlite');store.claim(request,brief,backend,dispatch_for(request,backend))
    with pytest.raises(Exception):store.claim(request,brief,{**backend,'executable':'/different'},dispatch_for(request,backend))


def test_historical_schema_replays_but_cannot_launch_with_unimplemented_retry_policy(tmp_path):
    request, brief, backend = inputs(tmp_path)
    from switchyard.provider_admission import CODEX_SOURCE_HEAD as historical
    request['codex_owner_head'] = historical
    request['switchyard_schema_sha256'] = 'sha256:131f1f6e0cf8cb0aea26ed225c584440c81ffedd443c68ace23adecbe493cf93'
    request['request_digest'] = digest(V3_DOMAIN+_canonical({k:v for k,v in request.items() if k!='request_digest'}))
    validate_request(request, brief)
    with pytest.raises(Exception):
        verify_backend({**backend,'codex_source_head':historical}, request)
    request['switchyard_schema_sha256'] = 'sha256:0e9c851cc9fad9538408ab44d84737d5f4d4d7ef39f2fd5db20c6f88fc7fbb9e'
    request['request_digest'] = digest(V3_DOMAIN+_canonical({k:v for k,v in request.items() if k!='request_digest'}))
    with pytest.raises(Exception): validate_request(request, brief)


def test_interim_pair_replays_but_cannot_select_final_backend(tmp_path):
    from switchyard.provider_admission import BETA_CODEX_SOURCE_HEAD
    request, brief, backend = inputs(tmp_path)
    request['codex_owner_head'] = BETA_CODEX_SOURCE_HEAD
    request['switchyard_schema_sha256'] = 'sha256:448c2535c9c9586754d222912bbc86bc09fadb3c98059dc134141aff08efb8ba'
    request['request_digest'] = digest(V3_DOMAIN+_canonical({k:v for k,v in request.items() if k!='request_digest'}))
    validate_request(request, brief)
    with pytest.raises(Exception):
        verify_backend({**backend, 'codex_source_head': BETA_CODEX_SOURCE_HEAD}, request)
    request['codex_owner_head'] = CODEX_SOURCE_HEAD
    request['request_digest'] = digest(V3_DOMAIN+_canonical({k:v for k,v in request.items() if k!='request_digest'}))
    with pytest.raises(Exception):
        validate_request(request, brief)


def test_actual_beta_snapshot_matches_its_closed_schema_not_historical(tmp_path):
    from jsonschema import Draft202012Validator
    request, brief, backend = inputs(tmp_path); Client.mode='completed'
    result=run(request,brief,backend,RunStore(tmp_path/'adapter.sqlite'),client_factory=Client)
    schemas=Path(__file__).resolve().parents[1]/'src/switchyard/schemas'
    beta=Draft202012Validator(json.loads((schemas/'switchyard.codex-provider-admission.beta-final.v1.schema.json').read_text()))
    beta.validate(result['provider_admission'])
    old=Draft202012Validator(json.loads((schemas/'switchyard.codex-provider-admission.v1.schema.json').read_text()))
    assert not old.is_valid(result['provider_admission'])
    interim=Draft202012Validator(json.loads((schemas/'switchyard.codex-provider-admission.beta.v1.schema.json').read_text()))
    assert not interim.is_valid(result['provider_admission'])


def test_beta_fixture_family_preserves_distinct_mapper_states():
    import runpy
    from jsonschema import Draft202012Validator
    root=Path(__file__).resolve().parents[1]
    emit=runpy.run_path(str(root/'qualification/provider_mapper_fixtures.py'))['snapshot']
    schema=Draft202012Validator(json.loads((root/'src/switchyard/schemas/switchyard.codex-provider-admission.beta-final.v1.schema.json').read_text()))
    expected={'completed':'PROVIDER_COMPLETED','parked':'PARKED_NOT_ADMITTED',
        'indeterminate':'ADMISSION_INDETERMINATE','interrupted':'POST_ADMISSION_INTERRUPTED','approval':'WAITING_APPROVAL'}
    for case,state in expected.items():
        snapshot=emit(case);schema.validate(snapshot)
        assert snapshot['mechanism_state']==state
        assert snapshot['binding']['executable_kind']=='DETERMINISTIC_FIXTURE'


@pytest.mark.parametrize('field', ['work_attempt_id', 'worker_start_request_digest', 'app_server_session_identity', 'adapter_protocol'])
def test_rehashed_dispatch_substitution_refused_before_contact(tmp_path, field):
    request,brief,backend=inputs(tmp_path)
    dispatch=dispatch_for(request,backend)
    dispatch[field]='sha256:'+'c'*64 if field.endswith('digest') else 'different'
    dispatch['dispatch_digest']=digest(DISPATCH_DOMAIN+_canonical({k:v for k,v in dispatch.items() if k!='dispatch_digest'}))
    Client.calls=[]
    with pytest.raises(Exception):
        actual_run(request,brief,backend,RunStore(tmp_path/'adapter.sqlite'),dispatch_record=dispatch,client_factory=Client)
    assert Client.calls==[]


def test_admitted_dispatch_occurrence_preserved_and_duplicate_change_refused(tmp_path):
    request,brief,backend=inputs(tmp_path);Client.mode='completed';Client.calls=[]
    store=RunStore(tmp_path/'adapter.sqlite');dispatch=dispatch_for(request,backend)
    result=actual_run(request,brief,backend,store,dispatch_record=dispatch,client_factory=Client)
    assert result['process_occurrence']==dispatch['adapter_process_occurrence_id']
    assert result['dispatch_record']==dispatch
    dispatch['adapter_process_occurrence_id']='different-admitted-occurrence'
    dispatch['dispatch_digest']=digest(DISPATCH_DOMAIN+_canonical({k:v for k,v in dispatch.items() if k!='dispatch_digest'}))
    with pytest.raises(Exception):
        actual_run(request,brief,backend,store,dispatch_record=dispatch,client_factory=Client)
    assert Client.calls==['initialize','thread/start','turn/start']


def test_inspect_missing_store_does_not_create(tmp_path):
    path=tmp_path/'absent.sqlite'
    with pytest.raises(Exception):inspect(path,'missing')
    assert not path.exists()


def test_reconcile_only_reads_same_turn_and_preserves_original(tmp_path):
    request,brief,backend=inputs(tmp_path);Client.mode='completed';Client.calls=[]
    path=tmp_path/'adapter.sqlite'
    result=run(request,brief,backend,RunStore(path),client_factory=Client)
    before=path.read_bytes(); Client.calls=[]
    read=reconcile(path,request['dispatch_occurrence_id'],client_factory=Client)
    assert read['state']=='OBSERVED_SAME_TURN'
    assert Client.calls==['initialize','thread/read']
    assert inspect(path,request['dispatch_occurrence_id'])==result
    assert path.read_bytes()==before


def test_captured_executable_is_sealed_and_path_replacement_does_not_rebind(tmp_path):
    import fcntl
    import os
    request,_,backend=inputs(tmp_path)
    source=tmp_path/'binary';source.write_bytes(Path('/usr/bin/true').read_bytes());source.chmod(0o700)
    backend['executable']=str(source)
    command,fd=verify_backend(backend,request)
    try:
        assert command[-2:] == ['-c', 'provider_retry_policy="disabled"']
        assert not any('model_providers.openai' in argument for argument in command)
        source.write_bytes(b'changed')
        os.lseek(fd,0,0)
        assert digest(os.read(fd,1024*1024))==backend['executable_sha256']
        assert fcntl.fcntl(fd,fcntl.F_GET_SEALS)&fcntl.F_SEAL_WRITE
        with pytest.raises(OSError):os.write(fd,b'changed')
    finally:os.close(fd)


def test_fd_relative_inputs_survive_root_pathname_replacement(tmp_path):
    visible=tmp_path/'visible'; held=tmp_path/'held'; outside=tmp_path/'outside'
    visible.mkdir(); outside.mkdir()
    expected=b'{"identity":"held"}'
    (visible/'request.json').write_bytes(expected)
    (outside/'request.json').write_bytes(b'{"identity":"substitute"}')
    root_fd=os.open(visible,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        visible.rename(held); visible.symlink_to(outside,target_is_directory=True)
        value,raw=load_at(root_fd,'request.json')
        assert raw==expected and value=={'identity':'held'}
    finally: os.close(root_fd)


@pytest.mark.parametrize('relative',['/absolute','../parent','a/../file','.', '',
                                     'a/./b','./a','a/.','a//b'])
def test_fd_relative_inputs_refuse_unbounded_names(tmp_path,relative):
    root_fd=os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        with pytest.raises(Exception): load_at(root_fd,relative)
    finally: os.close(root_fd)


@pytest.mark.parametrize('final', [False, True])
def test_fd_relative_inputs_refuse_symlink_component_or_final(tmp_path,final):
    outside=tmp_path/'outside'; outside.mkdir(); (outside/'x.json').write_text('{}')
    relative='linked' if final else 'linked/x.json'
    (tmp_path/'linked').symlink_to(outside/'x.json' if final else outside,
                                   target_is_directory=not final)
    root_fd=os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        with pytest.raises(Exception): load_at(root_fd,relative)
    finally: os.close(root_fd)


def test_fd_relative_closed_or_uninherited_descriptor_refuses(tmp_path):
    root_fd=os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); os.close(root_fd)
    with pytest.raises(Exception): load_at(root_fd,'request.json')


def test_fd_relative_descriptor_must_be_explicitly_inherited(tmp_path):
    (tmp_path/'request.json').write_text('{"ok":true}')
    root_fd=os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    code=('from switchyard.provider_runner import load_at; import sys; '
          'print(load_at(int(sys.argv[1]),"request.json")[0]["ok"])')
    environment={**os.environ,'PYTHONPATH':str(Path(__file__).resolve().parents[1]/'src')}
    try:
        inherited=subprocess.run([sys.executable,'-c',code,str(root_fd)],pass_fds=(root_fd,),env=environment,capture_output=True,text=True)
        omitted=subprocess.run([sys.executable,'-c',code,str(root_fd)],env=environment,capture_output=True,text=True)
    finally: os.close(root_fd)
    assert inherited.returncode==0 and inherited.stdout.strip()=='True'
    assert omitted.returncode!=0 and omitted.stdout==''


def test_fd_relative_state_preserves_duplicate_and_recovery_after_root_replacement(tmp_path):
    request,brief,backend=inputs(tmp_path); dispatch=dispatch_for(request,backend)
    visible=tmp_path/'state-root'; held=tmp_path/'held'; outside=tmp_path/'outside'
    visible.mkdir(); outside.mkdir(); root_fd=os.open(visible,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    store=RunStore(root_fd=root_fd,relative='adapter.sqlite')
    try:
        record,fresh=store.claim(request,brief,backend,dispatch); assert fresh
        visible.rename(held); visible.symlink_to(outside,target_is_directory=True)
        prior,again=store.claim(request,brief,backend,dispatch)
        assert not again and prior==record
        assert inspect('adapter.sqlite',request['dispatch_occurrence_id'],root_fd=root_fd)==record
        assert not list(outside.iterdir())
    finally: store.close(); os.close(root_fd)


def test_fd_relative_state_refuses_symlink_final(tmp_path):
    outside=tmp_path/'outside.sqlite'; outside.write_bytes(b'')
    (tmp_path/'adapter.sqlite').symlink_to(outside)
    root_fd=os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        with pytest.raises(Exception): RunStore(root_fd=root_fd,relative='adapter.sqlite')
        with pytest.raises(Exception): inspect('adapter.sqlite','missing',root_fd=root_fd)
    finally: os.close(root_fd)


def test_fd_relative_inspect_and_reconcile_use_held_original_after_root_replacement(tmp_path):
    request,brief,backend=inputs(tmp_path); Client.mode='completed'; Client.calls=[]
    visible=tmp_path/'visible-state'; held=tmp_path/'held-state'; outside=tmp_path/'outside-state'
    visible.mkdir(); outside.mkdir(); root_fd=os.open(visible,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    store=RunStore(root_fd=root_fd,relative='adapter.sqlite')
    try:
        original=run(request,brief,backend,store,client_factory=Client); store.close()
        visible.rename(held); visible.symlink_to(outside,target_is_directory=True); Client.calls=[]
        assert inspect('adapter.sqlite',request['dispatch_occurrence_id'],root_fd=root_fd)==original
        observed=reconcile('adapter.sqlite',request['dispatch_occurrence_id'],root_fd=root_fd,client_factory=Client)
        assert observed['state']=='OBSERVED_SAME_TURN'
        assert Client.calls==['initialize','thread/read'] and not list(outside.iterdir())
    finally: os.close(root_fd)
