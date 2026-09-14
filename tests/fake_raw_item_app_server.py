import json
import os
import sys

opt_out = set()
raw_events = False
bounded_fixture = os.environ.get("SWITCHYARD_FAKE_BOUNDED_PROVIDER")

def emit(method, params):
    # Codex97 transport.rs uses exact method membership per connection.
    if method not in opt_out:
        print(json.dumps({"method": method, "params": params, "emittedAtMs": 1000},
                         separators=(",", ":")), flush=True)

for line in sys.stdin:
    message = json.loads(line)
    method = message.get('method')
    if bounded_fixture and method == "thread/start":
        params = message["params"]
        raw_events = params.get("experimentalRawEvents") is True
        result = {"thread": {"id": "thread-test"}, "model": params["model"],
            "modelProvider": params["modelProvider"], "cwd": params["cwd"],
            "runtimeWorkspaceRoots": [], "instructionSources": [],
            "activePermissionProfile": {"id": "provider-bounded-read", "extends": None}}
        print(json.dumps({"id": message["id"], "result": result}), flush=True)
        continue
    if bounded_fixture and method == "turn/start":
        print(json.dumps({"id": message["id"], "result": {"turn": {"id": "turn-test"}}}), flush=True)
        common = {"threadId": "thread-test", "turnId": "turn-test"}
        text = message["params"]["input"][0]["text"]
        if raw_events:
            emit("rawResponseItem/completed", {**common, "item": {
                "type": "message", "id": "raw-user-item", "role": "user",
                "content": [{"type": "input_text", "text": text}],
                "internal_chat_message_metadata_passthrough": {
                    "turn_id": "turn-test", "create_time": 1000.5}}})
        if bounded_fixture == "unselected-large-frame":
            emit("unselected/raw-item", {"text": "x" * 17000})
        user = {"type": "userMessage", "id": "user-item", "clientId": None,
            "content": [{"type": "text", "text": text, "text_elements": []}]}
        emit("item/started", {**common, "item": user, "startedAtMs": 1000})
        emit("item/completed", {**common, "item": user, "completedAtMs": 1000})
        request = {**common, "requestOccurrenceId": "request-test", "samplingOrdinal": 0,
            "requestOrder": 0, "provider": "openai", "model": "gpt-5.6-terra"}
        emit("providerRequest/started", {**request, "startedAtMs": 1000})
        emit("rawResponse/started", {**request, "responseId": "response-test", "observedAtMs": 1001})
        if raw_events:
            emit("rawResponse/completed", {**common, "responseId": "response-test", "usage": None})
        agent = {"type": "agentMessage", "id": "agent-item", "text": "bounded finding",
            "phase": "final_answer", "memoryCitation": None, "delivery": None}
        emit("item/started", {**common, "item": agent, "startedAtMs": 1001})
        emit("item/completed", {**common, "item": agent, "completedAtMs": 1002})
        emit("turn/completed", {"threadId": "thread-test", "emittedAtMs": 1002, "turn": {
            "id": "turn-test", "items": [agent], "itemsView": "summary", "status": "completed",
            "error": None, "startedAt": 1, "completedAt": 2, "durationMs": 1000}})
        continue
    if method == 'initialize':
        opt_out = set(message.get('params', {}).get('capabilities', {}).get('optOutNotificationMethods', []))
        print(json.dumps({'id': message['id'], 'result': {'userAgent': 'local-raw-item-fixture'}}), flush=True)

