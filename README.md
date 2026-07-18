# ConsentScope: OAuth Permission and Trust Auditor

ConsentScope is a human-centered OAuth/OIDC authorization request auditor. It analyzes authorization request URLs and explains privacy, consent, and trust risks in both technical and plain language.

This tool was developed for the theme:

**Human, Privacy, & Trust-Centered Security**

## Problem Definition

OAuth and OpenID Connect consent screens often use technical permission names such as `openid`, `profile`, `email`, `offline_access`, `mail.read`, or `files.readwrite`. These scope names may be difficult for users to understand.

A user may approve an application without realizing that the application can read email, modify files, retain access after the session, or redirect through an insecure URL.

ConsentScope addresses this problem by analyzing OAuth/OIDC authorization request URLs and identifying risky consent and trust patterns.

## Why This Problem Matters

OAuth consent is a major part of modern authentication and authorization. Poorly explained or overly broad permissions can create privacy and security risks. Users need clearer explanations, and developers need a lightweight way to inspect authorization requests before deploying them.

## What Existing Tools Do

Existing security tools often focus on code scanning, network scanning, vulnerability detection, or identity-provider configuration. Fewer lightweight tools focus on the user-facing consent request itself and explain OAuth permissions in plain language.

## What Gap ConsentScope Fills

ConsentScope focuses on the human side of OAuth security. It translates scopes and request parameters into understandable findings, helping users and developers identify:

- broad permissions
- persistent access
- insecure redirect URIs
- missing `state`
- missing PKCE for public clients
- unknown or unexplained scopes
- excessive permission requests

## System Design

ConsentScope is a Python command-line tool.

High-level workflow:

1. Read an OAuth/OIDC authorization request URL.
2. Parse important parameters such as `client_id`, `redirect_uri`, `scope`, `state`, and PKCE fields.
3. Load a local JSON scope catalog.
4. Apply consent and trust rules.
5. Produce a technical report and a plain-language summary.
6. Optionally export JSON output.

## Technology Choices

- **Python 3**: portable and easy to run.
- **Standard library only**: no external dependencies.
- **JSON scope catalog**: easy to extend with new providers or permissions.
- **Command-line interface**: simple to reproduce and demonstrate.
- **Unit tests**: verifies parser and rule behavior.

## Project Structure

```text
consentscope-oauth-trust-auditor/
├── consentscope.py
├── rules/
│   └── scope_catalog.json
├── examples/
│   ├── safe-request.txt
│   ├── broad-access-request.txt
│   └── insecure-request.txt
├── results/
├── tests/
│   └── test_consentscope.py
├── README.md
├── requirements.txt
└── .gitignore
