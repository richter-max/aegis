# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in AEGIS (e.g., a bypass of the defense engine logic), please report it.

### Process

1.  **Do not** open a public issue.
2.  Email the maintainers at `max.richter.dev@proton.me` 
3.  Include a reproduction script (scenario) demonstrating the bypass.
4.  We will respond within 48 hours.

### Scope

- **In Scope**: Logic errors in `DefenseEngine`, `KeywordGuard`, or `SemanticGuard` that allow defined "bad" actions to pass.
- **Out of Scope**: Issues related to the underlying LLM's susceptibility to injection (we are the harness, not the model).
