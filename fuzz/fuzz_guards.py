import pytest
from hypothesis import given, strategies as st
from aegis.defenses.keyword_guard import KeywordGuard, KeywordGuardConfig
from aegis.defenses.semantic_guard import SemanticGuard, SemanticGuardConfig
from aegis.tools.send_email import ToolCall

# Strategy for generating random text
text_strategy = st.text(min_size=1, max_size=1000)

@given(text=text_strategy)
def test_keyword_guard_completeness(text):
    """Property: KeywordGuard should never crash on any string input."""
    guard = KeywordGuard(KeywordGuardConfig(keywords=["bad"]))
    call = ToolCall(name="send_email", args={"body": text})
    try:
        guard.decide(call, context_text="")
    except Exception as e:
        pytest.fail(f"KeywordGuard crashed on input '{text}': {e}")

@given(text=text_strategy)
def test_semantic_guard_completeness(text):
    """Property: SemanticGuard should never crash on any string input."""
    guard = SemanticGuard(SemanticGuardConfig.default())
    call = ToolCall(name="send_email", args={"body": text})
    try:
        guard.decide(call, context_text="")
    except Exception as e:
        pytest.fail(f"SemanticGuard crashed on input '{text}': {e}")

@given(prefix=text_strategy, suffix=text_strategy)
def test_keyword_guard_always_blocks_bad(prefix, suffix):
    """Property: KeywordGuard must always block if the bad keyword is present."""
    bad_word = "EXFILTRATE"
    # Create content that definitely contains the bad word
    # We must ensure bad_word is not broken by random generation, so we construct it.
    content = f"{prefix} {bad_word} {suffix}"
    
    guard = KeywordGuard(KeywordGuardConfig(keywords=["EXFILTRATE"]))
    call = ToolCall(name="send_email", args={"body": content})
    decision = guard.decide(call, context_text="")
    
    assert decision.blocked, f"Failed to block input containing 'EXFILTRATE': {content}"
