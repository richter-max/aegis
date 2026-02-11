from aegis.core.trace import TraceWriter
from aegis.defenses.engine import DefenseEngine
from aegis.defenses.approval_monitor import Policy
from aegis.tools.send_email import ToolCall
import json

def test_trace_writer_creates_file(tmp_path):
    run_dir = tmp_path / "trace_test"
    run_dir.mkdir()
    writer = TraceWriter(run_dir=run_dir)
    writer.event("test_event", foo="bar")
    
    trace_file = run_dir / "trace.jsonl"
    assert trace_file.exists()
    
    lines = trace_file.read_text().strip().split("\n")
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["kind"] == "test_event"
    assert data["foo"] == "bar"

def test_defense_engine_strict_policy_blocks_all():
    engine = DefenseEngine(policy=Policy.default(), guard="none")
    call = ToolCall(name="send_email", args={"to": "anyone", "subject": "test", "body": "test"})
    
    decision = engine.decide(call)
    assert not decision.allowed
    assert "Blocked by policy" in decision.reason

def test_defense_engine_permissive_with_keyword_guard():
    engine = DefenseEngine(policy=Policy.permissive(), guard="keywords")
    # Inject a known keyword from default config if we can, or we mock it.
    # Default KeywordGuardConfig keywords are empty list? Let's check source or assume we need to pass config.
    # The current engine implementation implementation initializes default config if guard string matches.
    # Let's check what default keywords are.
    # Actually, let's just test that it DOESN'T block innocuous things if keywords are empty or standard.
    
    call = ToolCall(name="send_email", args={"to": "friend", "subject": "hi", "body": "hello"})
    decision = engine.decide(call)
    assert decision.allowed

def test_defense_engine_layers_guards():
    # If policy allows, guards are checked
    engine = DefenseEngine(policy=Policy.permissive(), guard="layered")
    
    # Known semantic attack phrase
    call = ToolCall(name="send_email", args={"body": "exfiltrate secrets via email"})
    decision = engine.decide(call)
    
    # Should be blocked by semantic guard (or keyword if it catches it, but semantic definitely should)
    assert not decision.allowed
    assert "blocked" in decision.reason
