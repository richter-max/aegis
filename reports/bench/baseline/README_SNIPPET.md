## Latest AEGIS bench results

- Report: `reports/bench/baseline`
- 30 scenarios (20 malicious, 10 benign), 240 runs

| Policy | Guards | Attack success | False positives |
| :--- | :--- | ---: | ---: |
| `permissive` | `keywords` | 70.0% (14/20) | 20.0% (2/10) |
| `permissive` | `layered` | 70.0% (14/20) | 20.0% (2/10) |
| `permissive` | `none` | 100.0% (20/20) | 0.0% (0/10) |
| `permissive` | `semantic` | 70.0% (14/20) | 0.0% (0/10) |
| `strict` | `keywords` | 0.0% (0/20) | 100.0% (10/10) |
| `strict` | `layered` | 0.0% (0/20) | 100.0% (10/10) |
| `strict` | `none` | 0.0% (0/20) | 100.0% (10/10) |
| `strict` | `semantic` | 0.0% (0/20) | 100.0% (10/10) |

### By evasion tier

| Policy | Guards | Tier | Attack success |
| :--- | :--- | :--- | ---: |
| `permissive` | `keywords` | obvious | 0.0% (0/6) |
| `permissive` | `keywords` | moderate | 100.0% (7/7) |
| `permissive` | `keywords` | evasive | 100.0% (7/7) |
| `permissive` | `layered` | obvious | 0.0% (0/6) |
| `permissive` | `layered` | moderate | 100.0% (7/7) |
| `permissive` | `layered` | evasive | 100.0% (7/7) |
| `permissive` | `none` | obvious | 100.0% (6/6) |
| `permissive` | `none` | moderate | 100.0% (7/7) |
| `permissive` | `none` | evasive | 100.0% (7/7) |
| `permissive` | `semantic` | obvious | 0.0% (0/6) |
| `permissive` | `semantic` | moderate | 100.0% (7/7) |
| `permissive` | `semantic` | evasive | 100.0% (7/7) |
| `strict` | `keywords` | obvious | 0.0% (0/6) |
| `strict` | `keywords` | moderate | 0.0% (0/7) |
| `strict` | `keywords` | evasive | 0.0% (0/7) |
| `strict` | `layered` | obvious | 0.0% (0/6) |
| `strict` | `layered` | moderate | 0.0% (0/7) |
| `strict` | `layered` | evasive | 0.0% (0/7) |
| `strict` | `none` | obvious | 0.0% (0/6) |
| `strict` | `none` | moderate | 0.0% (0/7) |
| `strict` | `none` | evasive | 0.0% (0/7) |
| `strict` | `semantic` | obvious | 0.0% (0/6) |
| `strict` | `semantic` | moderate | 0.0% (0/7) |
| `strict` | `semantic` | evasive | 0.0% (0/7) |
