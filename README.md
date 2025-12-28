# Interface Poisoning Analyzer

A Python-based static analysis tool for detecting and quantifying **Interface Poisoning** in Java codebases.

## What is Interface Poisoning?

Interface Poisoning refers to the accumulation of unnecessary interface abstractions that:
- Have only one implementing class (speculative abstraction)
- Contain methods that are never called
- Create deep inheritance hierarchies that complicate navigation

This tool computes the **Interface Poisoning Index (IPI)** - a composite metric that quantifies the severity of interface-related complexity.

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/interface-poisoning-analyzer.git
cd interface-poisoning-analyzer

# Install dependencies
pip install javalang
```

## Usage

```bash
#General usage below:
python interface_poisoning_analyzer.py /path/to/java/project

#For this repostory, the src file already include https://github.com/apache/commons-cli.git src files.
#To run this example project, just make git clone and run script as below (with requirements):

python interface_poisoning_analyzer.py .\src
```

### Example

```bash
# Clone a sample Java project
git clone https://github.com/apache/commons-cli.git

# Run analysis
python interface_poisoning_analyzer.py ./commons-cli
```

## Output

The tool generates:
1. **Console Report** - Summary statistics and IPI scores for each interface
2. **JSON File** (`ipi_results.json`) - Detailed metrics for further analysis

### Sample Output

```
======================================================================
INTERFACE POISONING ANALYSIS REPORT
======================================================================

Project: ./commons-cli
Total Classes: 47
Total Interfaces: 9

----------------------------------------------------------------------
Interface               IC    SIR   IU   UUR    UMR   CD   NCD     IPI
----------------------------------------------------------------------
TypeHandler              1  1.000   1  0.021  0.500   3  1.000   0.772
Converter                6  0.167   8  0.170  0.000   1  0.000   0.166
----------------------------------------------------------------------

RISK DISTRIBUTION:
  HIGH (IPI > 0.7):   1 (11.1%)
  MEDIUM (0.4-0.7):   6 (66.7%)
  LOW (< 0.4):        2 (22.2%)
```

## IPI Formula

```
IPI = α · SIR + β · (1 - UUR) + γ · UMR + δ · NCD
```

Where:
| Metric | Name | Formula | Weight |
|--------|------|---------|--------|
| SIR | Single Implementation Risk | 1 / IC | α = 0.25 |
| UUR | Usage Utilization Rate | IU / C_total | β = 0.15 |
| UMR | Unused Method Rate | M_unused / M_total | γ = 0.25 |
| NCD | Normalized Call Depth | (CD-1) / (CD_max-1) | δ = 0.35 |

## Risk Classification

| Level | IPI Range | Recommendation |
|-------|-----------|----------------|
| 🔴 HIGH | > 0.7 | Immediate refactoring recommended |
| 🟡 MEDIUM | 0.4 - 0.7 | Review and consider simplification |
| 🟢 LOW | < 0.4 | Acceptable complexity |

## Requirements

- Python 3.6+
- javalang library

## Citation

If you use this tool in your research, please cite:

```
Taşkesen, A. A. (2025). Interface Poisoning: The Hidden Cost of 
Unnecessary Interfaces in Modern Codebases. UYMS 2025.
```

## License

MIT License

## Author

Ali Ahmet Taşkesen - Ankara Yıldırım Beyazıt University
