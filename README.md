Security Policy Linter
https://img.shields.io/badge/License-MIT-yellow.svg
https://img.shields.io/badge/python-3.8+-blue.svg

A command‑line tool to lint security policy documents for clarity, consistency, and contradictions.
It helps security teams, compliance officers, and policy authors identify problematic language and conflicting requirements.

✨ Features
Contradiction Detection – Finds conflicting numeric rules (e.g., password length: “minimum 8” vs “maximum 6”)

Vague Language Analysis – Flags subjective terms like appropriate, reasonable, periodically, sufficient

Weak Language Detection – Highlights advisory terms (should, may, could) in mandatory contexts

Overly Complex Sentences – Counts high‑density mandatory terms (must, shall, required)

Session Timeout Extraction – Parses and normalises timeout rules (minutes, hours, days, seconds)

Unit Normalisation – Converts mixed units (1 hour vs 60 minutes) for accurate comparison

Zero External Dependencies – Uses only the Python standard library

Comprehensive Test Suite – Over 140 tests ensure reliability

🚀 Installation
Option 1: Install from GitHub (recommended)
bash
pip install git+https://github.com/ts-satti/Security-Policy-Linter.git
Option 2: Install locally (after cloning)
bash
git clone https://github.com/ts-satti/Security-Policy-Linter.git
cd security-policy-linter
pip install .
After installation, the command spl will be available system‑wide.

📖 Usage
bash
spl [options] <policy_file> [<policy_file> ...]
Options
Option	Description
-t, --threshold	Maximum allowed mandatory terms per sentence (default: 2)
-v, --verbose	Show verbose output (including skipped lines)
--version	Display version and exit
Examples
Basic analysis

bash
spl password_policy.txt
Multiple files

bash
spl policy1.txt policy2.txt
Custom complexity threshold

bash
spl -t 3 security_policy.txt
📝 Example Output
Input (contradiction_test.txt):

text
Passwords must be at least 8 characters.
Passwords must be at most 6 characters.
Run:

bash
spl contradiction_test.txt
Output:

text
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
🧪 Testing
The project includes a comprehensive test suite using pytest.
To run the tests:

bash
pip install pytest          # if not already installed
pytest tests/
All tests should pass. The suite currently contains over 140 individual tests covering every component.

⚙️ Configuration
Currently, the lists of vague, weak, and boilerplate terms are hard‑coded in security_linter.py.
To customise:

Edit the global lists in the source file:

VAGUE_PHRASES

VAGUE_SINGLE_WORDS

RESPONSIBILITY_VAGUE_TERMS

WEAK_TERMS

PERMISSIVE_PATTERNS

BOILERPLATE_PATTERNS

Re‑install the package (pip install .) to apply changes.

A future version will support external configuration files (JSON/YAML).

📁 Project Structure
text
security-policy-linter/
├── security_linter.py          # Main CLI and analysis logic
├── policy_rule.py              # Immutable rule data model
├── tests/
│   ├── test_contradictions.py
│   ├── test_normalisation.py
│   ├── test_password_extraction.py
│   ├── test_policy_rule.py
│   ├── test_session_contradictions.py
│   ├── test_session_extraction.py
│   └── test_vague_precision.py
├── setup.py                     # Installation script
├── LICENSE                      # MIT License
├── README.md                    # This file
└── .gitignore                   # Git ignore rules
🗑️ Uninstalling
To remove the tool, use the package name (not the command name):

bash
pip uninstall security-policy-linter -y
This will delete the package and the spl command.

🤝 Contributing
Contributions are welcome! If you encounter a false positive or missing pattern:

Add a test case that reproduces the issue.

Modify the code to make the test pass.

Submit a pull request.

Please ensure all tests pass before submitting.

📄 License
This project is licensed under the MIT License – see the LICENSE file for details.

Built with ❤️ by [Your Name]
Now go lint your policies!