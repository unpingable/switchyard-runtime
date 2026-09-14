"""Emit explicitly deterministic beta mapper snapshots; no backend is spawned."""
import argparse
import hashlib
from pathlib import Path
from switchyard.appserver import AcquisitionCut, AcquisitionEnvelope, ServerMessage
from switchyard.nightshift_adapter import _canonical
from switchyard.provider_admission import FINAL_CODEX_SOURCE_HEAD, ProviderAdmissionMapper, replay_snapshot, seal_binding


def snapshot(case):
    producer=Path(__file__).resolve()
    binding=seal_binding(dict(work_attempt_id='beta-fixture-attempt',dispatch_occurrence_id='beta-fixture-dispatch',
        adapter_process_occurrence_id='beta-fixture-process',app_server_session_identity='beta-fixture-estate',
        thread_id='beta-fixture-thread',turn_id='beta-fixture-turn',provider='openai',model='gpt-5.6-terra',
        codex_source_head=FINAL_CODEX_SOURCE_HEAD,executable_kind='DETERMINISTIC_FIXTURE',
        app_server_executable_identity='qualification/provider_mapper_fixtures.py',
        app_server_executable_sha256='sha256:'+hashlib.sha256(producer.read_bytes()).hexdigest(),
        internal_provider_request_retries=0))
    mapper=ProviderAdmissionMapper(binding)
    ordinal=0
    def event(method,params,approval=False):
        nonlocal ordinal
        value=dict(method=method,params=params)
        if approval: value['id']=77
        mapper.consume_envelope(AcquisitionEnvelope(ordinal,'SERVER_REQUEST' if approval else 'NOTIFICATION',
            ServerMessage(value,_canonical(value)+b'\n')))
        ordinal+=1
    common=dict(threadId=binding['thread_id'],turnId=binding['turn_id'],requestOccurrenceId='beta-fixture-request',
        samplingOrdinal=0,requestOrder=0,provider='openai',model='gpt-5.6-terra')
    event('providerRequest/started',dict(common,startedAtMs=1788900000000))
    if case=='parked':
        event('providerAdmission/refused',dict(common,responseCreated=False,willRetry=False,refusalKind='modelAtCapacity',
            codexErrorInfo='serverOverloaded',retryAfterMs=5000,diagnostic='Explicit deterministic capacity fixture',observedAtMs=1788900000001))
    elif case=='indeterminate':
        mapper.mark_acquisition_loss('explicit deterministic interrupted acquisition')
    else:
        event('rawResponse/started',dict(common,responseId='beta-fixture-response',observedAtMs=1788900000001))
        if case=='approval':
            event('rawResponse/completed',dict(threadId=binding['thread_id'],turnId=binding['turn_id'],responseId='beta-fixture-response',usage=None))
            event('item/commandExecution/requestApproval',dict(threadId=binding['thread_id'],turnId=binding['turn_id']),True)
        elif case=='interrupted':
            mapper.mark_acquisition_loss('explicit deterministic post-admission interruption')
        else:
            event('rawResponse/completed',dict(threadId=binding['thread_id'],turnId=binding['turn_id'],responseId='beta-fixture-response',usage=None))
            event('turn/completed',dict(threadId=binding['thread_id'],turn=dict(id=binding['turn_id'],status='completed')))
    if case != 'approval':
        mapper.consume_cut(AcquisitionCut(True,0,'EXITED',ordinal,binding['adapter_process_occurrence_id'],binding['app_server_session_identity']))
    result=mapper.snapshot(); replay_snapshot(result)
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();args.out.mkdir(exist_ok=False)
    for case in ('completed','parked','indeterminate','interrupted','approval'):
        (args.out/(case+'.json')).write_bytes(_canonical(snapshot(case)))
