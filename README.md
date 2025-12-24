 ### 📦 Project name

 **SentinelSecrets**

*🔐 Secret Scanner for CI/CD & Git Hooks*

SentinelSecrets is an open-source tool for preventing secret leaks
(API keys, tokens, passwords) in Git repositories and CI/CD.

### 🎯 Project Summary

A tool that automatically prevents secrets (API keys, tokens, passwords) from leaking before code is pushed to the repository:

- Checks git diffs before committing

- Uses regular expressions + entropy analysis

- Suitable for local development and CI/CD

- Generates reports in JSON and Markdown

- Has a REST API with OpenAPI (Swagger)

### 🧱 Architecture

~~~bash
sentinel-secrets/
├── sentinel/
│   ├── __init__.py
│   ├── scanner.py
│   ├── entropy.py
│   ├── git_utils.py
│   ├── ignore.py
│   └── report.py
├── hooks/
│   └── pre-commit        # git pre-commit hook
├── tests/
│   └── test_scanner.py
├── examples/
│   └── example_report.md
├── .sentinelignore
├── .pre-commit-hooks.yaml
├── .pre-commit-config.yaml
├── main.py
├── README.md
├── SECURITY.md
├── LICENSE
└── requirements.txt

~~~

### 🧠 Core logic (key fragments)

**🔍 Regex + entropy search**

**📊 Entropy**

**Git pre-commit hook**

**🌐 REST API (Swagger)**

Swagger will be available on:

~~~bash
http://localhost:8000/docs
~~~

## Features

- Git pre-commit scanning
- Regex + entropy analysis
- JSON/Markdown reports
- REST API with OpenAPI
- Suitable for CI/CD

## Installation
~~~bash
git clone https://github.com/mscbuild/sentinel-secrets-.git
cd sentinel-secrets-
pip install -r requirements.txt
~~~

### Usage

~~~bash
python main.py --file app.py
~~~

### Architecture

- scanner.py — signatures and search logic

- entropy.py — random secret detection

- git_utils.py — working with git diff

- api.py — REST API

### Threats this addresses

- API key leaks to public repositories

- Cloud account compromise

- SOC2/ISO 27001 compliance violations

- Supply chain attacks

### 🧪 How to run tests

~~~bash
pip install pytest
pytest -v
~~~

![SentinelSecrets Scan](https://github.com/mscbuild/sentinel-secrets-/actions/workflows/sentinel.yml/badge.svg)


### 📜 LICENSE (MIT)

MIT License

Copyright (c) 2025 Mscbuild
