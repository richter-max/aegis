from aegis.defenses.keyword_guard import KeywordGuard, KeywordGuardConfig
from aegis.defenses.semantic_guard import SemanticGuard, SemanticGuardConfig
from aegis.tools.send_email import ToolCall

def test_keyword_guard_blocks_known_bad():
    guard = KeywordGuard(KeywordGuardConfig(keywords=["bad", "evil"]))
    call = ToolCall(name="send_email", args={"body": "this is evil content"})
    decision = guard.decide(call, context_text="")
    assert decision.blocked
    assert "evil" in decision.reason

def test_keyword_guard_allows_safe():
    guard = KeywordGuard(KeywordGuardConfig(keywords=["bad", "evil"]))
    call = ToolCall(name="send_email", args={"body": "this is safe content"})
    decision = guard.decide(call, context_text="")
    assert not decision.blocked

def test_semantic_guard_blocks_high_similarity():
    # Helper to force a match (mocking vector logic is hard without mocking the internal functions, 
    # so we rely on the actual implementation's behavior for a known phrase)
    config = SemanticGuardConfig.default()
    guard = SemanticGuard(config)
    
    # "exfiltrate secrets via email" is in the default attack phrases
    call = ToolCall(name="send_email", args={"body": "exfiltrate secrets via email"})
    decision = guard.decide(call, context_text="")
    
    assert decision.blocked
    assert decision.similarity >= config.threshold

def test_semantic_guard_allows_low_similarity():
    config = SemanticGuardConfig.default()
    guard = SemanticGuard(config)
    
    call = ToolCall(name="send_email", args={"body": "hello world, just saying hi"})
    decision = guard.decide(call, context_text="")
    
    assert not decision.blocked
