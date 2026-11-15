# Detection and Analysis of Memory Corruption Vulnerabilities in C/C++

**Degree Project:** Master's / Bachelor's Thesis  
**Language:** English  

---

## 1. Project Overview

Memory safety violations in systems software written in C and C++—such as buffer overflows, Use-After-Free (UAF), Double Free, and race conditions—remain among the most persistent and critical attack vectors in modern computing. 

This project aims to design, implement, and evaluate a **lightweight, reproducible benchmarking and analysis framework** to systematically assess both dynamic and static detection mechanisms against C/C++ memory corruption vulnerabilities.

By leveraging standardized test suites (specifically [Juliet Test Suite for C v1.3](https://github.com/arichardson/juliet-test-suite-c)) alongside dedicated real-world synthetic test cases, this framework evaluates detection tools across critical metrics:
* **Detection Efficacy:** True Positive (TP), True Negative (TN), False Positive (FP), and False Negative (FN) rates.
* **Performance Overhead:** Execution time penalty (CPU and wall-clock) and memory footprint expansion (Peak RSS).
* **Detection Latency:** At what stage the violation is intercepted (compilation, runtime onset, deferred deallocation).
* **Diagnostic Quality:** Depth and accuracy of error reporting (call stacks, allocation/deallocation traces, memory address shadow maps).

---

## 2. Research Scope & Evaluation Matrix

### Target Vulnerability Classes (CWEs)
* **CWE-121:** Stack-based Buffer Overflow
* **CWE-122:** Heap-based Buffer Overflow
* **CWE-124 / CWE-127:** Buffer Underwrite / Underread
* **CWE-415:** Double Free
* **CWE-416:** Use After Free (UAF)
* **CWE-476:** NULL Pointer Dereference
* **CWE-362:** Race Conditions (Concurrent Memory Corruption)

### Analyzed Detection Mechanisms
| Tool / Mechanism | Type | Focus Areas |
| :--- | :--- | :--- |
| **Baseline (Native)** | Uninstrumented | Baseline performance reference (`-O0`, `-O2`) |
| **AddressSanitizer (ASan)** | Dynamic (Compiler-based) | Out-of-bounds accesses, UAF, Double Free |
| **UndefinedBehaviorSanitizer (UBSan)** | Dynamic (Compiler-based) | Integer overflows, pointer misalignment, null deref |
| **Valgrind Memcheck** | Dynamic (Binary Instrumentation) | Uninitialized memory reads, invalid heap access; leaks reported separately |
| **Clang Static Analyzer / Clang-Tidy** | Static Analysis (AST/Engine) | Path-sensitive vulnerability scanning |
| **Cppcheck** | Static Analysis (Pattern/AST) | Static flow anomalies and misuse patterns |

---

## 3. Project Roadmap

```
  +-----------------------------------------------------------+
  | Stage 1: Environment Setup (macOS / Ubuntu ARM64)         |
  +-----------------------------------------------------------+
                                |
                                v
  +-----------------------------------------------------------+
  | Stage 2: Juliet Test Suite Exploration & Dataset Selection|
  +-----------------------------------------------------------+
                                |
                                v
  +-----------------------------------------------------------+
  | Stage 3: Baseline Manual Experiments (ASan vs Valgrind)   |
  +-----------------------------------------------------------+
                                |
                                v
  +-----------------------------------------------------------+
  | Stage 4: Framework Architecture & Interface Design        |
  +-----------------------------------------------------------+
                                |
                                v
  +-----------------------------------------------------------+
  | Stage 5: Implementation (Python CLI, Tool Drivers, Loggers)|
  +-----------------------------------------------------------+
                                |
                                v
  +-----------------------------------------------------------+
  | Stage 6: Automated Experiments & Statistical Analysis     |
  +-----------------------------------------------------------+
                                |
                                v
  +-----------------------------------------------------------+
  | Stage 7: Thesis Writing, Visualizations & Recommendations |
  +-----------------------------------------------------------+
```

* **Stage 1: Environment Preparation:**
  * Host environment: macOS (development, CLI design, local test builds).
  * Target benchmark environment: Ubuntu ARM64 (Linux container/VM providing full native ASan, Valgrind, and hardware performance counter support).
  * Toolchains: Clang/LLVM, GCC, CMake, Python 3.10+, Valgrind.
  * Ingestion of Juliet testcases.
* **Stage 2: Juliet Suite Exploration:**
  * Analysis of testcase structure (`CWE..._bad`, `CWE..._good`, multi-file test splits).
  * Extraction of ground-truth metadata and expected outcomes.
* **Stage 3: Initial Manual Experiments:**
  * Baseline execution without sanitizers.
  * ASan instrumentation comparison against Valgrind Memcheck.
  * Diagnostic report comparison and latency observation.
* **Stage 4: Framework Design:**
  * Modular design: Compiler Engine, Tool Runner, Output Parser, Metrics Collector, Report Exporter.
  * Uniform CLI interface.
* **Stage 5: Implementation:**
  * Python modular framework with extensible tool plugins.
  * Structured export formats: JSON (detailed per-test logs) and CSV (aggregated benchmarking tables).
* **Stage 6: Experimental Evaluation:**
  * Large-scale execution across selected CWE classes.
  * Repeated trials for statistical confidence ($\bar{x}$, standard deviation, confidence intervals).
* **Stage 7: Results & Thesis Publication:**
  * Charts: Detection accuracy matrices, execution slowdown factors, peak memory multipliers.
  * Architectural trade-off analysis and industry recommendations for CI/CD integration.

---

## 4. Repository Structure

```text
.
├── AGENTS.md                  # Detailed instructions and code standards for AI assistants
├── README.md                  # Project overview and documentation (this file)
├── requirements.txt           # Python dependencies for the framework
├── benchmark/                 # Test suites and testcase definitions
│   ├── juliet/                # Juliet test suite subsets and manifests
│   └── synthetic/             # Custom minimal reproducible memory bugs
├── runner/                    # Python-based benchmarking framework
│   ├── main.py                # Framework entry point (CLI)
│   ├── framework/             # Core engine
│   │   ├── __init__.py
│   │   ├── compiler.py        # Clang/GCC compiler drivers and flag injectors
│   │   ├── executor.py        # Process executor with timeouts & resource monitoring
│   │   ├── metrics.py         # Performance and diagnostic metric calculations
│   │   ├── reporter.py        # JSON / CSV report generators
│   │   └── analysis/          # Reusable benchmark analysis package
│   │       ├── inputs.py      # Load and validate JSON / CSV results
│   │       ├── statistics.py  # Detection and performance statistics
│   │       ├── plots.py       # Summary charts
│   │       └── pipeline.py    # Summary and chart generation
│   └── tools/                 # Tool-specific adapter drivers
│       ├── __init__.py
│       ├── base.py            # Abstract Base Tool interface
│       ├── asan.py            # AddressSanitizer driver & log parser
│       ├── valgrind.py        # Valgrind Memcheck driver & XML/log parser
│       ├── ubsan.py           # UndefinedBehaviorSanitizer driver
│       └── static_clang.py    # Clang Static Analyzer / Clang-Tidy driver
├── results/                   # Experimental data outputs
│   ├── raw/                   # Raw tool outputs and execution logs
│   ├── json/                  # Structured JSON test run results
│   └── csv/                   # Aggregated metrics for analysis and plotting
└── docs/                      # Thesis notes, methodology documentation 
```

---

## 5. Getting Started

### Prerequisites

#### Linux (Ubuntu ARM64 / x86_64 - Recommended for Experiments)
```bash
sudo apt update
sudo apt install -y build-essential clang llvm cmake valgrind python3 python3-pip python3-venv
```

#### macOS (Development)
```bash
brew install llvm cmake python
# Note: Valgrind is run in Linux VM/Docker on macOS ARM64 due to platform limitations.
```

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/c-cpp-memory-framework-analysis.git
   cd c-cpp-memory-framework-analysis
   ```

2. Set up the Python virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. Download and set up the Juliet Test Suite target CWEs:
   ```bash
   ./benchmark/setup_juliet.sh
   ```

### Usage (CLI Preview)

```bash
# Run a specific Juliet testcase with AddressSanitizer (evaluating vulnerable bad path)
python3 runner/main.py run --tool asan --file benchmark/juliet/testcases/CWE121_Stack_Based_Buffer_Overflow/s05/CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_memmove_01.c --flavor bad

# Run the safe path on the same testcase (expecting True Negative)
python3 runner/main.py run --tool asan --file benchmark/juliet/testcases/CWE121_Stack_Based_Buffer_Overflow/s05/CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_memmove_01.c --flavor good

# Run benchmark comparison across multiple tools on synthetic or Juliet suites
python3 runner/main.py benchmark --tools native,asan --dir benchmark/synthetic --csv results/csv/summary.csv

# Analyze the CSV results and generate summary statistics and charts
python3 runner/main.py analyze --input results/csv/benchmark_run.csv --output-dir results/analysis
```

The `analyze` command also accepts the framework's JSON export. It writes per-tool,
per-CWE, and per-flavor summaries plus confusion-matrix, detection-rate, and performance
charts.
The analysis functionality is also available as the `runner.framework.analysis`
Python package (`load_results`, `analyze_results`, and `generate_analysis`); the CLI
uses the same package. `runner.framework.analyzer` remains as a compatibility import.
TP/FP/TN/FN are derived at testcase level; execution errors and timeouts are excluded
from classification and performance averages. When a testcase has repeated measurements,
its confusion-matrix classification uses only the first measured run (repetition 1).
Later repetitions provide performance measurements and a separate run-to-run stability
check; they do not add votes or increase the testcase sample size. Detection stability
and performance summaries are separated by `good` and `bad` flavor. Confusion-matrix
proportions include Wilson confidence intervals. Performance first takes the median of
valid repetitions within each testcase, then summarizes across testcases. Percentile
bootstrap confidence intervals resample testcase-level estimates (configurable with
`--confidence-level`); repetitions are not treated as independent testcases. If
repetition 1 errors, that testcase is excluded from the confusion matrix; later valid
runs may still contribute performance measurements.

Benchmarks default to **5 measured repetitions** per testcase, flavor, and tool and run
no warmups. For each testcase/flavor, each tool is compiled once; compilation is
excluded from measured results. Tools run in a seeded randomized order (`--seed 42` by
default). Use `--filter` or `--limit` for a pilot subset; inspect within-testcase
variability and increase `--repetitions` only if the pilot indicates that more
measurements are needed. Repetition count is an explicit protocol setting, not an
automatic stopping rule. Every measured run is saved as its own JSON/CSV row with its
repetition, `used_for_classification` flag, position in that repetition's tool order,
planned repetition count, and random seed. Older exports with additional metadata
fields remain analyzable. The classification flag is true only for a successful
repetition 1. Measured execution and timeout failures are saved as `ERROR` rows.

`repeatability.png` summarizes within-testcase coefficient of variation for wall-clock
time and peak RSS, separately by flavor. The performance chart also labels each
tool/flavor separately; its standard deviation describes variation between testcases.
The confusion matrix still gives each testcase only one classification based on
repetition 1. Older one-run CSV files remain analyzable, but cannot provide within-case
repeatability estimates.

Analysis reports paired wall-clock overhead relative to the uninstrumented `native`
baseline separately for `good` and `bad` flavors. Runs are paired by testcase, CWE,
flavor, stdin, and repetition. Each paired ratio is `tool_time / native_time`; the
median ratio within each testcase is summarized across testcases and bootstrapped.
Overhead is `(ratio - 1) * 100`; the summary also includes slowdown factors, paired
repetition counts, and within-testcase overhead variation. Runs without a matching
native repetition or with a zero baseline duration are excluded. Paired peak-RSS
overhead uses the same pairing and aggregation method, with a memory multiplier. Peak
RSS is sampled for each launched process every millisecond; it is no longer taken from
`RUSAGE_CHILDREN`, whose maximum is cumulative across child processes. Sampling can miss
very short memory spikes, and a process that exits before its first sample has no RSS
value; those pairs are omitted from the peak-RSS overhead calculation.

The analysis summary reports paired slowdown and RSS multiplier statistics separately
for `good` and `bad`: median, arithmetic mean, geometric mean for slowdown, and
confidence intervals for the reported location statistics. Each point estimate is
calculated across testcase-level medians; bootstrap intervals resample those testcase
estimates, never individual repetitions. The CLI displays the median, mean, and
geometric mean slowdown and the median and mean RSS multiplier with their bootstrap
intervals. `summary.json` also retains each testcase-level paired estimate.

The analysis output includes `wall_clock_slowdown_boxplot.png` and
`peak_rss_multiplier_boxplot.png`, which compare testcase-level paired estimates
(logarithmic y-axis when all values are positive); `detection_heatmap.png`, which
shows each testcase's first-run TP/FP/TN/FN classification by tool; and
`detection_stability_good.png` / `detection_stability_bad.png`, which show the
fraction of valid measured runs with a detection for each testcase and tool. The
stability heatmaps annotate detected runs over valid runs; execution errors are
excluded from their denominators and remain reported separately. Heatmap labels
shorten Juliet testcase names to their function suffix for readability; full paths
remain available in `summary.json`.

The runner supplies `10` on stdin for Juliet CWE-121/CWE-129 `fgets` and `fscanf`
testcases, for both flavors: the bad path exercises the out-of-bounds index, while the
good path exercises its bounds check. The input is recorded in JSON and CSV results.
Memcheck results for stack-array overflows should be interpreted per CWE and alongside
the raw Valgrind error summary; Memcheck may not report every out-of-bounds access
within a stack frame. Existing result files are not changed automatically; rerun the
benchmark to capture both the deterministic stdin fixture and the corrected per-process
RSS values. Older RSS values cannot be repaired during analysis because they contain
only the previous cumulative child-process maximum.

Valgrind leak checking remains enabled, but leak kinds are excluded from its error exit
status because the confusion matrix measures the target memory-corruption CWE, not
incidental leaks. Leak summaries are retained as `MEMORY_LEAK` diagnostics; they do not
set `detected` or turn a safe target-CWE case into a false positive. For example, some
Juliet CWE-416 good variants intentionally leave an allocation unfreed while avoiding
the use-after-free sink. If memory leaks are a target in a future experiment, they
should be evaluated as a separate CWE/metric. CSV exports include byte and block counts
for definitely lost, indirectly lost, possibly lost, still reachable, and suppressed
memory; fields are blank when no leak summary was reported.

---

## 6. Output Data Format

The framework outputs benchmark results in structured formats:

* **JSON (`results/json/`):** Contains exact compiler commands, execution exit codes, raw stderr/stdout, parsed memory violation type, stack trace summaries, execution duration, and peak memory usage.
* **CSV (`results/csv/`):** Flat tabular structure optimized for Pandas, R, and LaTeX table generation (e.g., `testcase_id`, `cwe`, `tool`, `expected_outcome`, `detected`, `classification`, `cpu_time_s`, `peak_rss_kb`).

---

## 7. License & Academic Attribution

This project is licensed under the [MIT License](LICENSE) - see the [LICENSE](LICENSE) file for details.

Developed as part of an academic thesis in Cybersecurity by **Patryk Kurek**. Test cases from the Juliet Test Suite are in the public domain or subject to NIST / ISPRAS licensing terms.
