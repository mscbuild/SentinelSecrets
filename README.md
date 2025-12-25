 ### 📦 Project name - **SentinelSecrets**
 
 ![](https://komarev.com/ghpvc/?username=mscbuild) 
 ![](https://img.shields.io/github/license/mscbuild/sentinel-secrets-) 
 ![](https://img.shields.io/github/languages/code-size/mscbuild/sentinel-secrets-)
![](https://img.shields.io/badge/PRs-Welcome-green)
![](https://img.shields.io/badge/code%20style-python-green)
![](https://img.shields.io/github/stars/mscbuild)
![](https://img.shields.io/badge/Topic-Github-lighred)
![](https://img.shields.io/website?url=https://github.com/mscbuild)

*🔐 Secret Scanner for CI/CD & Git Hooks*

SentinelSecrets is an open-source tool for preventing secret leaks
(API keys, tokens, passwords) in Git repositories and CI/CD.The project integrates directly into the development process via Git hooks, blocking a commit if a secret is detected in it.

### 🎯 Project Summary

A tool that automatically prevents secrets (API keys, tokens, passwords) from leaking before code is pushed to the repository:

- Checks git diffs before committing

- Uses regular expressions + entropy analysis

- Suitable for local development and CI/CD

- Generates reports in JSON and Markdown

- Has a REST API with OpenAPI (Swagger)

### ✅ Benefits and Problems Solved

- **Leak Prevention:** Stops secrets from leaking into public and corporate repositories.
- **Risk Mitigation (Shift Left Security):** Security is checked at the coding stage, not after deployment.
- **Audit Automation:** Report generation in JSON format allows for easy integration into corporate security dashboards.

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
├── pyproject.toml
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

> [!IMPORTANT]  
> Use `git filter-repo` (recommended) or BFG Repo-Cleaner to remove secrets from Git history.


> [!NOTE]  
> My project is lightweight, customizable to the company's internal formats, and written in pure Python for easy auditing.

### 🛡️ Security

This project is developed in compliance with the OWASP Code Review Guide.

### 📜 LICENSE (MIT)

MIT License

Copyright (c) 2025 Mscbuild
