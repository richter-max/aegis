# Threat Model: AEGIS Security Evaluation Harness

## 1. System Overview

AEGIS is a harness for evaluating the security of tool-using AI agents. It acts as a "sandbox" or "proxy" between a simulated Agent and the Tools (e.g., Email, File System).

### Data Flow Diagram

```mermaid
graph TD
    User[User / Researcher] -->|Configures| Harness[AEGIS Harness]
    Attacker[External Attacker] -->|Injects Payload| Content[Untrusted Content (Web/Email)]
    
    subgraph "AEGIS Trusted Boundary"
        Harness -->|Prompts| Agent[Simulated Agent]
        Agent -->|Proposes Tool Call| Defense[Defense Engine]
        
        Defense -->|Inspects| Guard[Guardrails (Keyword/Semantic)]
        Guard -->|Verdict| Defense
        
        Defense -->|Allowed?| Execution[Tool Execution (Mocked)]
        Execution -->|Result| Agent
    end
    
    Content -->|Read by| Agent
```

## 2. Trust Boundaries

1.  **Untrusted Input**: Content retrieved from external sources (web pages, emails) which may contain Indirect Prompt Injections.
2.  **Agent Logic**: The LLM/Agent itself is considered "semi-trusted". It is not malicious but can be compromised/coerced.
3.  **Tool Execution**: The actual execution of tools is the "Critical Asset". We must prevent unauthorized tool usage.

## 3. STRIDE Analysis

| Category | Threat | Mitigation in AEGIS |
| :--- | :--- | :--- |
| **Spoofing** | Attacker impersonates a legitimate user to trigger tools. | N/A (Local harness). Future: AuthN for remote agents. |
| **Tampering** | Attacker modifies the prompt history or context to bypass guards. | **Defense Engine**: Immutable logging of all events to `trace.jsonl`. |
| **Repudiation** | An agent performs an action, but there is no record of why. | **Traceability**: Full audit log of Prompt -> Thought -> Action -> Verdict. |
| **Information Disclosure** | Agent leaks sensitive data (keys, PII) to an attacker via tool calls. | **Output Filtering** (Planned): Semantic analysis of outgoing tool arguments. |
| **Denial of Service** | Agent enters an infinite loop of tool calls, consuming budget. | **Budget Limits**: Max turns configuration. |
| **Elevation of Privilege** | Agent breaks out of the harness to execute arbitrary system commands. | **Sandboxing**: Tools are mocked or strictly scoped (Python functions, not shell). |

## 4. Acceptance Criteria for Security

- [ ] All tool calls MUST pass through the `DefenseEngine`.
- [ ] No direct shell execution allowed in default tools.
- [ ] All "blocked" actions must be logged with the specific guardrail that triggered.
