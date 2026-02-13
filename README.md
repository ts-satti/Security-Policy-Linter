# 🔐 Security Policy Linter

![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)

A command-line tool to lint **security policy documents** for **clarity, consistency, and contradictions**.

It helps **security teams, compliance officers, auditors, and policy authors** identify problematic language and conflicting requirements before audits or incidents occur.

---

## ✨ Features

- **Contradiction Detection**  
  Finds conflicting numeric rules (e.g. *“minimum 8 characters”* vs *“maximum 6 characters”*)

- **Vague Language Analysis**  
  Flags subjective terms like *appropriate*, *reasonable*, *periodically*, *sufficient*

- **Weak Language Detection**  
  Highlights advisory terms (*should*, *may*, *could*) in mandatory contexts

- **Overly Complex Sentences**  
  Detects sentences with excessive mandatory terms (*must*, *shall*, *required*)

- **Session Timeout Extraction**  
  Parses and normalises timeout rules (minutes, hours, days, seconds)

- **Unit Normalisation**  
  Converts mixed units (e.g. *1 hour* vs *60 minutes*) for accurate comparison

- **Zero External Dependencies**  
  Uses only the Python standard library

- **Extensive Test Coverage**  
  Over **140 automated tests** ensure correctness and reliability

---

## 🚀 Installation

### Option 1: Install from GitHub (recommended)

pip install git+[(https://github.com/ts-satti/Security-Policy-Linter.git)](https://github.com/ts-satti/Security-Policy-Linter.git)
### **Option 2: Install locally (after cloning)**
```bash
git clone [https://github.com/yourusername/security-policy-linter.git](https://github.com/ts-satti/Security-Policy-Linter.git)
cd security-policy-linter
pip install .
After installation, the spl command will be available system-wide.
```
### 📖 Usage
```bash
spl [options] <policy_file> [<policy_file> ...]
```
### Options

| Option | Description |
| :--- | :--- |
| `-t, --threshold` | Maximum mandatory terms per sentence (default: 2) |
| `-v, --verbose` | Show verbose output (including skipped lines) |
| `--version` | Display version and exit |

### Examples
# Basic analysis
```bash
spl password_policy.txt
```
### Multiple files
```bash
spl policy1.txt policy2.txt
```
### Custom complexity threshold
```bash
spl -t 3 security_policy.txt
```
## 📝 Example Output
### Input (contradiction_test.txt)
```bash
Passwords must be at least 8 characters.
Passwords must be at most 6 characters.
```
### Run
```bash
spl contradiction_test.txt
```

### Output
```bash
Analyzing: contradiction_test.txt
Complexity Threshold: 2 mandatory terms

🔍 Found 1 potential issue(s):
--------------------------------------------------------------------------------

1. Contradiction
   Subject: password_min_length
   Lines 1 and 2:
     - "Passwords must be at least 8 characters."
     - "Passwords must be at most 6 characters."
   Contradictory values: 8.0 vs 6.0 characters
--------------------------------------------------------------------------------
💡 Suggestion: Review flagged items and clarify where possible.
```
### 🧪 Testing
The project includes a comprehensive test suite using `pytest`.  
To run the tests:

```bash
pip install pytest          # if not already installed
pytest tests/
```

### ⚙️ Configuration
** Currently, the lists of vague, weak, and boilerplate terms are hard-coded in security_linter.py.**

**Customisable Lists**

- VAGUE_PHRASES
- VAGUE_SINGLE_WORDS
- RESPONSIBILITY_VAGUE_TERMS
- WEAK_TERMS
- PERMISSIVE_PATTERNS
- BOILERPLATE_PATTERNS

**After editing, reinstall the package:
**
```bash
pip install .
```
#### Future versions will support external configuration files (JSON/YAML).

## 📁 Project Structure

```text
security-policy-linter/
├── security_linter.py          # CLI entry point & analysis logic
├── policy_rule.py              # Immutable rule data model
├── tests/                      # Automated test suite
│   ├── test_contradictions.py
│   ├── test_normalisation.py
│   ├── test_password_extraction.py
│   ├── test_policy_rule.py
│   ├── test_session_contradictions.py
│   ├── test_session_extraction.py
│   └── test_vague_precision.py
├── setup.py                    # Packaging & installation
├── LICENSE                     # MIT License
├── README.md                   # Documentation
└── .gitignore
```
## 🗑️ Uninstalling
### To remove the tool, use the package name (not the command name):
```bash
pip uninstall security-policy-linter -y
```
**This removes both the package and the spl command.
**
### 🤝 Contributing
Contributions are welcome.

If you encounter a false positive or missing pattern:      
Add a test case that reproduces the issue.   
Modify the code to make the test pass.  

Submit a pull request.

Please ensure all tests pass before submitting.

### 📄 License
This project is licensed under the [MIT License](LICENSE).
See the LICENSE file for details.

**Built with ❤️ by Tashmam Shafique Satti.**         
Now go lint your policies!
