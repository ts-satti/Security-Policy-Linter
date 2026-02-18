from setuptools import setup, find_packages

setup(
    name="security-policy-linter",
    version="1.3.2",
    description="Lint security policy documents for contradictions, vague language, and weak requirements.",
    author="Tashmam Shafique Satti",
    author_email="tushamumsatti@gmail.com",
    url="https://github.com/ts-satti/Security-Policy-Linter",
    py_modules=["security_linter", "policy_rule"],
    entry_points={
        "console_scripts": [
            "spl = security_linter:main",  
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    extras_require={
        "pdf": ["pypdf>=3.0.0"],
        "docx": ["python-docx>=0.8.11"],
        "all": ["pypdf>=3.0.0", "python-docx>=0.8.11"],
    },
    python_requires=">=3.8",
)