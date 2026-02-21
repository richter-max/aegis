# AEGIS Examples

This directory contains ready-to-run examples demonstrating core AEGIS workflows.

## Run a Security Scenario

```bash
# Install AEGIS
pip install -e .

# Run the tool exfiltration scenario under strict policy
aegis run --scenario tool_exfiltration --policy strict
```

## Compare Policy Effectiveness

```bash
# Run the benchmark across all built-in scenarios
aegis bench --config ../configs/experiments/basic.json
```

This produces a report in `reports/bench/` with attack success rates per policy/guard combination.

## Try the Demo Attack Vectors

```bash
# Indirect injection demo (hidden instructions in web page)
aegis run --scenario indirect_injection_01 --policy permissive --demo-indirect

# Context fragmentation demo (payload split across turns)
aegis run --scenario context_fragmentation_01 --policy strict --demo-fragment

# Token smuggling demo (Base64-encoded payload)
aegis run --scenario token_smuggling_01 --policy strict --demo-smuggling
```

## Evaluate a Run

```bash
# Evaluate the most recent run and write metrics.json
aegis eval --latest
```

## See the Dashboard

```bash
pip install streamlit
streamlit run dashboard/app.py
```
