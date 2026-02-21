# AEGIS Design Rationale

> This document explains the non-obvious design decisions in AEGIS and the threat model they address.

## Why Evaluation is Separate from the Agent

The evaluation engine (`aegis eval`) reads from a trace log that the agent *writes to*, but cannot modify after the fact. The evaluator runs in a separate process with no dependency on the agent's internal state.

This is intentional. An agent evaluated by its own runtime is equivalent to a program checking its own test results — the grader and the subject share the same trust boundary, which eliminates the grader's independence. AEGIS enforces harness separation by design.

## Why Tools are Mocked

Executing `send_email` or `delete_file` against real infrastructure during a security test creates two problems:

1. **Side effects**: A misconfigured policy or buggy guard could cause real damage.
2. **Non-reproducibility**: Real tool calls introduce external dependencies that break determinism.

All tools in AEGIS are mocked at the interface level. They accept real arguments, evaluate whether they *would* succeed, log the decision, but never touch real infrastructure. This means the worst case is a logged "email sent" event — not a real exfiltration.

## Why N-gram Cosine Similarity (Not an LLM)

The semantic guard uses n-gram overlap to detect obfuscated payloads with zero external dependencies. This is deliberate:

- **Determinism**: Same input → same block/allow decision, always.
- **Auditability**: The similarity score is fully explainable (bag-of-ngrams dot product).
- **No model drift**: LLM-based guards can change behaviour when the model is updated.

The trade-off is recall — n-gram similarity will miss novel phrasings. That trade-off is acceptable because the goal is reproducible benchmarking, not production deployment. A production system would layer this with LLM-based reasoning; AEGIS benchmarks the n-gram baseline to establish a floor.

## Why the Trust Boundary is Between Input and Agent

The root cause of prompt injection is the absence of trust tagging on content entering the agent's context. When a web page response, user message, and system instruction are concatenated into the same context window with no provenance information, the agent has no mechanism to distinguish authoritative instructions from adversarial ones.

AEGIS models this explicitly: untrusted content is tagged as `source: untrusted` in the trace before it reaches the policy layer. This trace annotation is what makes forensic analysis possible after the fact.

## Why Permissive Policy is Not a Bug

The permissive policy intentionally allows high-risk tool calls. This creates a controlled baseline:

- Attack success rate under permissive = theoretical maximum impact.
- Attack success rate under strict + layered guards = actual residual risk.
- The delta is the measurable value of the defense stack.

Without a permissive baseline, you cannot quantify how much the defenses are actually contributing.
