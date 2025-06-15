# VulKGraph: C/C++ Vulnerability Propagation Analysis

This repository contains the implementation of **Algorithm 1: Comprehensive Software Reuse Detection** from our paper "VulnGraph: Quantitative Analysis of Vulnerability Propagation in the C/C++ Software Ecosystem Using Knowledge Graphs".


## Implementation

### Core Algorithm
- **CodeCloneDetector.py**: Main implementation of Algorithm 1
- **Enhanced Centris**: Temporal-aware reuse detection with adaptive thresholds  
- **Multi-source Integration**: Code clone detection + SBOM analysis


## Quick Start

```python
from CodeCloneDetector import CodeCloneDetector

# Configure paths and thresholds
config = {
    'base_threshold': 0.1,
    'hamming_threshold': 8,
    'oss_path': '/path/to/oss/repos/',
    'ccscanner_path': '/path/to/ccscanner/results/'
}

# Run detection
detector = CodeCloneDetector(config)
detector.build_tpl_feature_library()
results = detector.detect_all_reuse(project_path, project_name, project_author)
```

## Experimental Setup

### Environment
- Python 3.7+
- Neo4j 4.4.20
- Git (for temporal analysis)

## Repository Structure

```
document/
├── CodeCloneDetector.py           # Algorithm 1 implementation
├── step_0_Node.py                 # Knowledge graph node definitions
├── step_1_Preprocess.py           # Data preprocessing
├── step_2_Relationship.py         # Relationship extraction
├── step_3_process_CVE.py          # CVE processing
├── step_4_PatchNodeExtraction.py  # Patch extraction  
├── step_5_VulnerabilityPropagation.py # Propagation analysis
└── data/                          # Experimental data
```

## Citation

```bibtex
@article{vulgraph2025,
  title={VulGraph: Quantitative Analysis of Vulnerability Propagation in the C/C++ Software Ecosystem Using Knowledge Graphs},
  author={Anonymous},
  year={2025}
}
```

## Limitations

- Supports Type-1 to Type-3 code clones (Type-4 semantic clones require advanced analysis)
- Requires complete Git history for temporal analysis
- Function extraction based on regex patterns (may miss complex definitions)

---

**Contact**: Anonymous submission for review 