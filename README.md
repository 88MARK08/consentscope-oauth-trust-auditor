# ConsentScope: OAuth Permission and Trust Auditor

## Overview

ConsentScope is a defensive security and privacy review tool for OAuth and OpenID Connect authorization requests. It analyzes authorization request URLs and produces a report that combines technical findings with plain-language explanations of what the requested permissions may allow.

The tool is designed to help users, developers, and security reviewers understand consent and trust risks before an OAuth request is approved or deployed.

ConsentScope does not validate whether an OAuth client is legitimate, does not contact an identity provider, and does not inspect live consent screens. It provides a reproducible local workflow for reviewing authorization request structure, scope choices, and consent-related risk indicators.

---

## Table of Contents

1. [Problem Definition](#problem-definition)
2. [Why This Matters](#why-this-matters)
3. [Existing Tools and Approaches](#existing-tools-and-approaches)
4. [Gap Filled by ConsentScope](#gap-filled-by-consentscope)
5. [System Design](#system-design)
6. [Detection Coverage](#detection-coverage)
7. [Technology Choices](#technology-choices)
8. [Repository Structure](#repository-structure)
9. [Installation](#installation)
10. [How to Run](#how-to-run)
11. [Example Output](#example-output)
12. [Validation and Testing](#validation-and-testing)
13. [Evaluation](#evaluation)
14. [Known Issues and Limitations](#known-issues-and-limitations)
15. [Future Work](#future-work)
16. [Resources](#resources)
17. [Declaration of Generative AI Usage](#declaration-of-generative-ai-usage)
18. [Author](#author)

---

## Problem Definition

OAuth and OpenID Connect authorization requests often contain technical parameters such as `scope`, `redirect_uri`, `state`, `code_challenge`, and `code_challenge_method`.

A user may approve an application without clearly understanding that the application is requesting access to email, files, calendar data, or long-lived access through refresh tokens. Developers may also accidentally create authorization requests with risky settings, such as missing `state`, missing PKCE for public clients, broad scopes, unknown scopes, or insecure redirect URIs.

ConsentScope addresses this problem by parsing OAuth/OIDC authorization request URLs and identifying consent, privacy, and trust risks in a form that is useful to both technical reviewers and non-specialist users.

---

## Why This Matters

OAuth consent is part of the trust boundary between a user, an application, and an identity provider. Poorly explained permissions can lead users to approve access they do not fully understand.

ConsentScope helps answer questions such as:

- Is the redirect URI using HTTPS?
- Is the request missing a `state` parameter?
- Is a public client missing PKCE?
- Is PKCE configured with a weaker method?
- Does the request ask for persistent access through `offline_access`?
- Does the request include broad or sensitive permissions?
- Are there unknown scopes that the local catalog cannot explain?
- Can the requested permissions be summarized in plain language?


---

## Existing Tools and Approaches

Common approaches for reviewing OAuth and identity flows include:

- Identity-provider admin consoles
- OAuth and OIDC debugging tools
- Browser developer tools
- Application security reviews
- Manual inspection of authorization URLs
- Enterprise identity governance platforms
- Cloud security posture and identity security tools

These approaches are useful, but they may require infrastructure, provider access, or manual review. ConsentScope provides a focused local workflow for reviewing authorization request URLs and translating technical scope names into user-centered explanations.

---

## Gap Filled by ConsentScope

ConsentScope focuses on the consent request itself. It fills the gap between manual URL inspection and full identity-governance platforms.

It provides a reproducible environment for:

- Parsing OAuth/OIDC authorization request URLs
- Reviewing important authorization parameters
- Mapping scopes to plain-language explanations
- Detecting consent and trust risk patterns
- Producing terminal and JSON reports
- Testing safer and riskier authorization examples

ConsentScope supports identity and application-security review by making OAuth consent risks easier to inspect, explain, and reproduce from a saved authorization request URL.

---

## System Design

ConsentScope has four main parts.

### 1. Authorization Request Parser

The parser reads an OAuth/OIDC authorization request URL from either a command-line argument or a text file. It extracts fields such as:

- `response_type`
- `client_id`
- `redirect_uri`
- `scope`
- `state`
- `code_challenge`
- `code_challenge_method`
- `prompt`
- `access_type`

### 2. Scope Catalog

The `rules/scope_catalog.json` file maps known scopes to:

- severity
- technical description
- plain-language user meaning

This design makes the scope explanations adjustable without changing the Python source code.

### 3. Rule Engine

The rule engine checks for consent and trust concerns, including insecure redirect URIs, missing `state`, missing PKCE, broad scopes, unknown scopes, duplicate scopes, and requests with many scopes.

### 4. Reporting

ConsentScope prints a terminal report and can also write JSON output to the `results/` directory. Each finding includes a severity, rule ID, technical message, and plain-language explanation.

### Detection Flow

    OAuth URL
       |
       v
    Parser
       |
       v
    Scope Catalog + Rule Engine
       |
       v
    Technical Findings + Plain-Language Summary
       |
       v
    Terminal Report or JSON Report

---

## Detection Coverage

| Detection | Description | Severity |
|---|---|---:|
| Insecure redirect URI | Detects redirect URIs that are not HTTPS or approved local development addresses | High |
| Missing redirect URI | Detects requests without a `redirect_uri` parameter | High |
| Missing state | Detects authorization requests without a `state` parameter | Medium |
| Missing PKCE | Detects public-client requests without a `code_challenge` | Medium |
| Weak PKCE method | Detects PKCE requests where `code_challenge_method` is not `S256` | Low |
| Excessive scope count | Detects requests asking for many scopes at once | Medium |
| Duplicate scopes | Detects repeated scopes in the same request | Low |
| Unknown scopes | Detects scopes not explained by the local catalog | Low |
| Persistent access | Detects `offline_access` | Medium |
| Sensitive file access | Detects file read/write style scopes | High |
| Sensitive mail access | Detects mail read or mail send style scopes | High |
| Calendar access | Detects calendar read or write style scopes | Medium or High |

---

## Technology Choices

| Technology | Purpose |
|---|---|
| Python 3 | Main implementation language |
| `urllib.parse` | Authorization URL parsing |
| JSON | Scope catalog and report output |
| `unittest` | Regression testing |
| Bash | Reproducible command-line workflow |

Python was chosen because it is readable, widely available, and suitable for building a reproducible security-review prototype. The tool uses only the Python standard library.

---

## Repository Structure

    consentscope-oauth-trust-auditor/
    ├── README.md
    ├── requirements.txt
    ├── consentscope.py
    ├── rules/
    │   └── scope_catalog.json
    ├── examples/
    │   ├── safe-request.txt
    │   ├── broad-access-request.txt
    │   └── insecure-request.txt
    ├── results/
    │   └── README.md
    └── tests/
        └── test_consentscope.py

---

## Installation

Clone the repository:

    git clone https://github.com/88MARK08/consentscope-oauth-trust-auditor.git
    cd consentscope-oauth-trust-auditor

Create and activate a Python virtual environment:

    python3 -m venv .venv
    source .venv/bin/activate

Install requirements:

    python -m pip install --upgrade pip
    pip install -r requirements.txt

The `requirements.txt` file documents that ConsentScope currently uses only the Python standard library.

---

## How to Run

Display help:

    python3 consentscope.py --help

Analyze the safer example:

    python3 consentscope.py \
      --url examples/safe-request.txt \
      --client-type public

Analyze the broad-access example:

    python3 consentscope.py \
      --url examples/broad-access-request.txt \
      --client-type public

Analyze the insecure example:

    python3 consentscope.py \
      --url examples/insecure-request.txt \
      --client-type public

Generate JSON output:

    python3 consentscope.py \
      --url examples/broad-access-request.txt \
      --client-type public \
      --output results/broad-access-report.json

View the JSON report:

    cat results/broad-access-report.json

---

## Example Output

For the broad-access example, ConsentScope reports findings such as:

    [HIGH] Redirect URI is not HTTPS or approved local development: http://example.com/callback
          User meaning: The user may be redirected through a less secure address.

    [HIGH] Scope requested: mail.read — Allows reading user mail.
          User meaning: read your email messages

    [HIGH] Scope requested: mail.send — Allows sending mail as the user.
          User meaning: send email from your account

The broad-access example produces:

    Risk score: 100/100

---

## Validation and Testing

ConsentScope uses unit tests to validate parser and rule behavior.

Run:

    python3 -m unittest discover -s tests

Current expected result:

    Ran 3 tests

    OK

The test suite verifies that:

- the safer request does not produce high-severity findings
- the broad-access request detects major risks
- insecure redirect behavior is detected
- missing `state` is detected
- missing PKCE is detected
- weak PKCE configuration is detected
- unknown scopes are detected
- the broad-access risk score reaches 100/100

---

## Evaluation

ConsentScope was evaluated against three synthetic OAuth/OIDC authorization request examples.

| Example | Purpose | Expected Result |
|---|---|---|
| `safe-request.txt` | Lower-risk authorization request | Low risk score, no high findings |
| `broad-access-request.txt` | Broad permissions and insecure redirect | High risk score, multiple findings |
| `insecure-request.txt` | Unknown scope and weak PKCE | Detects insecure and unknown elements |

Current local validation result:

    Ran 3 tests in 0.001s

    OK

The broad-access request was also run manually and produced a risk score of:

    100/100

---

## Known Issues and Limitations

ConsentScope is a prototype and has several limitations:

- The local scope catalog is small.
- Provider-specific scope semantics may differ.
- The tool does not contact live Google, Microsoft, GitHub, Okta, or other identity-provider metadata endpoints.
- The tool does not verify whether a `client_id` is legitimate.
- The tool does not inspect the actual rendered consent screen.
- The tool does not validate whether the authorization server is configured securely.
- Risk scoring is rule-based and may require tuning for production environments.
- Unknown scopes require manual review.
- Findings should be interpreted in context before making a security decision.

---

## Future Work

Possible extensions include:

- provider-specific scope catalogs
- GitHub, Google, Microsoft, and Okta scope profiles
- HTML consent-screen review
- browser extension mode
- SARIF output for security-tool integration
- CSV and Markdown report output
- CI integration for application-security review
- privacy-impact categories for each scope
- severity tuning based on provider and application type
- detection of overprivileged OAuth applications from exported app inventories

---

## Resources

- [OAuth 2.0 Framework, RFC 6749](https://www.rfc-editor.org/rfc/rfc6749)
- [Proof Key for Code Exchange, RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)
- [OAuth 2.0 Security Best Current Practice, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0-final.html)
- [OAuth 2.0 for Native Apps, RFC 8252](https://www.rfc-editor.org/rfc/rfc8252)

---

## Declaration of Generative AI Usage

During development, ChatGPT was used for editing, grammar improvement, documentation refinement, and generating artificial or synthetic example authorization requests. The author reviewed and revised the assisted content and takes full responsibility for the final design, implementation, testing, and submission.

---

## Author

**Markjoe Uba**
