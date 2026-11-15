# Project overview

**Title:** Detection and Analysis of Memory Corruption Vulnerabilities in C/C++  
**Author:** Patryk Kurek
**Field of Study:** Cybersecurity  
**Purpose:** Academic experimental evaluation framework for memory safety tools in C/C++.

### Objective & Core Mission
The system evaluates dynamic (ASan, UBSan, Valgrind) and static (Clang-Tidy, Cppcheck) analysis tools against classic C/C++ memory corruption vulnerabilities (Buffer Overflows, Use-After-Free, Double Free, etc.) sourced from the NIST Juliet Test Suite (`juliet-dynamic`) and synthetic benchmarks.

Key measurement dimensions:
1. **Detection Accuracy:** Ground truth verification (`good` vs `bad` implementations), calculating True Positives (TP), True Negatives (TN), False Positives (FP), False Negatives (FN).
2. **Performance Overhead:** Execution duration (wall-clock / user CPU time) and memory overhead (Peak RSS).
3. **Diagnostic Quality:** Parsing tool logs to verify whether the tool correctly identifies the exact bug type, file, and line number.
4. **Reproducibility:** Structured output logs in JSON (detailed) and CSV (aggregated metrics).

### Target Platforms
- **Development & Prototyping:** macOS (Apple Silicon / ARM64). Note: Dynamic instrumentation tools like ASan are supported on macOS; Valgrind is unsupported or severely restricted on modern macOS.
- **Benchmark Execution & Experiments:** Ubuntu ARM64 (Linux container / UTM / native VM). All dynamic tools (including Valgrind Memcheck) run in this target Linux environment for uniform, publication-grade results.

### Architectural Blueprint
```
runner/
├── main.py                  # CLI entry point (subcommands: compile, run, benchmark, report)
├── framework/
│   ├── compiler.py          # Compiler abstraction (Clang, GCC) + flag injection
│   ├── executor.py          # Process execution engine with timeout & resource tracking
│   ├── models.py            # Dataclasses / schemas for test cases and evaluation results
│   ├── parser.py            # Diagnostic output parsers (ASan traces, Valgrind XML/text)
│   └── reporter.py          # JSON and CSV export handlers
└── tools/
    ├── base.py              # Abstract ToolAdapter base class
    ├── native.py            # Baseline uninstrumented execution
    ├── asan.py              # AddressSanitizer driver
    ├── ubsan.py             # UndefinedBehaviorSanitizer driver
    ├── valgrind.py          # Valgrind Memcheck runner & parser
    └── static_clang.py      # Clang Static Analyzer / Clang-Tidy driver
```

---

# Build and test commands

### Virtual Environment & Dependencies
```bash
# Initialize and activate Python venv
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements.txt
```

### Framework Linting & Formatting
```bash
# Code style and type checking
ruff check .
black --check .
mypy runner/
```

### Automated Framework Tests
```bash
# Run unit and integration tests with pytest
pytest tests/ -v
```

### CLI Execution Examples
```bash
# Run a single synthetic test with Native baseline
python3 runner/main.py run --tool native --file benchmark/synthetic/cwe121_stack_overflow.c --flavor bad

# Run single test with AddressSanitizer
python3 runner/main.py run --tool asan --file benchmark/synthetic/cwe121_stack_overflow.c --flavor bad

# Run comparative benchmark across multiple tools
python3 runner/main.py benchmark --tools native,asan --suite synthetic --output results/csv/test_results.csv
```

---

# Code style guidelines

### Python Guidelines (Framework Engine)
1. **Python Version:** Python 3.10+ required.
2. **Type Hints:** All function and method signatures must include strict type annotations (`typing.Optional`, `typing.List`, `typing.Dict`, `Path`, etc.).
3. **Data Modeling:** Use `dataclasses` or `pydantic` models for structured entities (`TestCase`, `ToolResult`, `ExecutionMetrics`). Avoid passing raw, unstructured dictionaries across module boundaries.
4. **Error Handling:** Avoid bare `except:`. Handle expected process errors (`subprocess.TimeoutExpired`, `subprocess.CalledProcessError`) explicitly and log detailed diagnostics.
5. **Path Handling:** Use `pathlib.Path` instead of string manipulations or raw `os.path`.
6. **Logging:** Use Python's standard `logging` library instead of ad-hoc `print()` statements for diagnostic and debugging outputs. Reserve CLI output formatting for user-facing commands.
7. **Clean Subprocess Execution:** Always enforce timeouts on compiled binaries (`timeout_seconds=10` default) to prevent infinite loops or hung processes during crashes.

### C/C++ Testcase Guidelines
1. **Standards:** C testcases must conform to C99 / C11 standards (`clang -std=c99`). C++ testcases must conform to C++11 / C++17.
2. **Deterministic Behavior:** Testcases must not rely on interactive user input (`stdin`). Hardcode deterministic inputs or pass parameters via `argv`.
3. **Juliet Compatibility:** Maintain Juliet's naming conventions:
   - `*_bad()`: Triggers the designated memory safety violation.
   - `*_good()`: Implements safe memory management (no vulnerability).
4. **Standalone Execution:** Provide a minimal `main()` entrypoint or preprocessor switches (`#ifdef INCLUDEMAIN`) allowing individual files to compile cleanly without missing symbols.

---

# Testing instructions

### 1. Framework Unit Tests
- Location: `tests/`
- Every component (`compiler.py`, `executor.py`, `parser.py`, and each tool adapter in `runner/tools/`) must have corresponding unit tests.
- Mock process executions where appropriate to test error handling, timeout handling, and log parsing without requiring external compilers.

### 2. Integration Tests with Synthetic Test Cases
- Location: `benchmark/synthetic/`
- Maintain a collection of minimal, isolated C programs representing each target CWE:
  - `cwe121_stack_overflow.c`
  - `cwe122_heap_overflow.c`
  - `cwe415_double_free.c`
  - `cwe416_uaf.c`
- Test that each tool detects the `bad` branch (True Positive) and succeeds without alerts on the `good` branch (True Negative).

### 3. Evaluating Juliet Benchmark Testcases
- Ground-truth validation:
  - Execute `good` variant $\rightarrow$ Expect zero alerts, exit code 0 ($\rightarrow$ True Negative if passed, False Positive if alerted).
  - Execute `bad` variant $\rightarrow$ Expect crash / sanitizer error ($\rightarrow$ True Positive if intercepted, False Negative if undetected).
- Record and aggregate metrics into `results/json/` and `results/csv/`.
