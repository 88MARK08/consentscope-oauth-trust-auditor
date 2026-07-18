# ConsentScope: OAuth Permission and Trust Auditor

ConsentScope is a human-centered OAuth/OIDC authorization request auditor. It analyzes authorization request URLs and explains privacy, consent, and trust risks in both technical and plain language.

## Problem Definition

OAuth and OpenID Connect consent screens often use technical permission names such as `openid`, `profile`, `email`, `offline_access`, `mail.read`, or `files.readwrite`. These scope names may be difficult for users to understand.

A user may approve an application without realizing that the application can read email, modify files, retain access after the session, or redirect through an insecure URL.

ConsentScope addresses this problem by analyzing OAuth/OIDC authorization request URLs and identifying risky consent and trust patterns.

## Why This Problem Matters

OAuth consent is a major part of modern authentication and authorization. Poorly explained or overly broad permissions can create privacy and security risks. Users need clearer explanations, and developers need a practical way to inspect authorization requests before deploying them.

## What Existing Tools Do

Existing security tools often focus on code scanning, network scanning, vulnerability detection, or identity-provider configuration. Fewer tools focus on the user-facing consent request itself and explain OAuth permissions in plain language.

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

- Python 3: portable and easy to run.
- Standard library only: no external dependencies.
- JSON scope catalog: easy to extend with new providers or permissions.
- Command-line interface: simple to reproduce and demonstrate.
- Unit tests: verifies parser and rule behavior.

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
│   └── README.md
├── tests/
│   └── test_consentscope.py
├── README.md
├── requirements.txt
└── .gitignore
```

## Installation

Clone the repository:

```bash
git clone https://github.com/88MARK08/consentscope-oauth-trust-auditor.git
cd consentscope-oauth-trust-auditor
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install requirements:

```bash
pip install -r requirements.txt
```

ConsentScope currently uses only the Python standard library, so no external packages are required.

## Usage

Analyze the safer example:

```bash
python3 consentscope.py --url examples/safe-request.txt --client-type public
```

Analyze the broad-access example:

```bash
python3 consentscope.py --url examples/broad-access-request.txt --client-type public
```

Analyze the insecure example:

```bash
python3 consentscope.py --url examples/insecure-request.txt --client-type public
```

Generate JSON output:

```bash
python3 consentscope.py \
  --url examples/broad-access-request.txt \
  --client-type public \
  --output results/broad-access-report.json
```

View JSON output:

```bash
cat results/broad-access-report.json
```

## Example Findings

For the broad-access request, ConsentScope detects issues such as:

- non-HTTPS redirect URI
- missing `state` parameter
- missing PKCE for a public client
- too many requested scopes
- persistent access through `offline_access`
- file read/write permissions
- mail read permissions
- mail send permissions

Example output:

```text
Risk score: 100/100
```

## Testing

Run the unit tests:

```bash
python3 -m unittest discover -s tests
```

Expected result:

```text
Ran 3 tests

OK
```

The tests verify that:

- the safer request does not produce high-severity findings
- the broad-access request detects major risks
- unknown scopes are detected
- insecure redirect behavior is detected
- weak PKCE configuration is detected

## Results

ConsentScope successfully analyzes three example authorization requests:

| Example | Purpose | Expected Result |
|---|---|---|
| `safe-request.txt` | Lower-risk OAuth request | Low risk score, no high findings |
| `broad-access-request.txt` | Broad permissions and insecure redirect | High risk score, multiple findings |
| `insecure-request.txt` | Unknown scope and weak PKCE | Detects insecure and unknown elements |

## Known Issues

ConsentScope is a prototype. Current limitations include:

- The scope catalog is intentionally small.
- It does not connect to live Google, Microsoft, GitHub, or Okta metadata.
- It does not validate whether a `client_id` is legitimate.
- It does not inspect actual consent screens.
- Risk scoring is rule-based and may need tuning for production use.

## Future Improvements

Possible improvements include:

- provider-specific scope catalogs
- HTML consent-screen analysis
- browser extension mode
- CI integration
- detection of overprivileged OAuth applications
- mapping scopes to privacy impact categories
- SARIF output for security tooling integration

## Reproducibility

The tool is reproducible because it uses:

- Python 3
- local example URLs
- a local JSON rule catalog
- standard-library parsing
- unit tests

A user can clone the repository, run the example commands, and reproduce the same findings.
