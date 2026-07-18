#!/usr/bin/env python3
"""
ConsentScope: A Human-Centered OAuth Permission and Trust Auditor

This tool analyzes OAuth/OIDC authorization request URLs and explains
privacy, consent, and trust risks in both technical and plain language.
"""

import argparse
import json
import os
from urllib.parse import urlparse, parse_qs


LOCALHOST_HOSTS = {"localhost", "127.0.0.1", "::1"}


def load_scope_catalog(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def read_input(value):
    if os.path.exists(value):
        with open(value, "r", encoding="utf-8") as f:
            return f.read().strip()
    return value.strip()


def parse_authorization_request(raw_url):
    parsed = urlparse(raw_url)
    query = parse_qs(parsed.query)

    def first(name):
        values = query.get(name, [])
        return values[0] if values else None

    scopes = []
    scope_value = first("scope")
    if scope_value:
        scopes = scope_value.split()

    return {
        "raw_url": raw_url,
        "scheme": parsed.scheme,
        "host": parsed.netloc,
        "path": parsed.path,
        "response_type": first("response_type"),
        "client_id": first("client_id"),
        "redirect_uri": first("redirect_uri"),
        "scope": scope_value,
        "scopes": scopes,
        "state": first("state"),
        "code_challenge": first("code_challenge"),
        "code_challenge_method": first("code_challenge_method"),
        "prompt": first("prompt"),
        "access_type": first("access_type"),
    }


def classify_redirect_uri(redirect_uri):
    if not redirect_uri:
        return "missing"

    parsed = urlparse(redirect_uri)

    if parsed.scheme == "https":
        return "https"

    if parsed.scheme == "http" and parsed.hostname in LOCALHOST_HOSTS:
        return "local_dev"

    return "insecure"


def analyze_request(req, catalog, client_type):
    findings = []
    scopes = req["scopes"]

    def add(severity, rule_id, message, plain_language):
        findings.append({
            "severity": severity,
            "rule_id": rule_id,
            "message": message,
            "plain_language": plain_language,
        })

    redirect_status = classify_redirect_uri(req["redirect_uri"])

    if redirect_status == "missing":
        add(
            "HIGH",
            "redirect-uri-missing",
            "No redirect_uri parameter was found.",
            "The request does not clearly show where the user will be sent after approval."
        )
    elif redirect_status == "insecure":
        add(
            "HIGH",
            "redirect-uri-insecure",
            f"Redirect URI is not HTTPS or approved local development: {req['redirect_uri']}",
            "The user may be redirected through a less secure address."
        )

    if not req["state"]:
        add(
            "MEDIUM",
            "state-missing",
            "No state parameter was found.",
            "The request may be more exposed to login or consent flow tampering."
        )

    if client_type == "public":
        if not req["code_challenge"]:
            add(
                "MEDIUM",
                "pkce-missing",
                "Public client request does not include a PKCE code_challenge.",
                "The login flow may have weaker protection against authorization-code interception."
            )
        elif req["code_challenge_method"] != "S256":
            add(
                "LOW",
                "pkce-method-not-s256",
                "PKCE is present, but code_challenge_method is not S256.",
                "The request uses a weaker or unclear PKCE method."
            )

    if len(scopes) != len(set(scopes)):
        add(
            "LOW",
            "duplicate-scopes",
            "Duplicate scopes were requested.",
            "The permission request may be poorly configured or unnecessarily repeated."
        )

    if len(scopes) >= 8:
        add(
            "MEDIUM",
            "many-scopes",
            f"The request contains many scopes: {len(scopes)}.",
            "The application is asking for many permissions at once, which may be hard for users to understand."
        )

    known_scopes = catalog.get("scopes", {})

    for scope in scopes:
        info = known_scopes.get(scope)

        if not info:
            add(
                "LOW",
                "unknown-scope",
                f"Unknown or uncatalogued scope requested: {scope}",
                "This permission is not explained by the local scope catalog."
            )
            continue

        severity = info.get("severity", "INFO")
        if severity in {"LOW", "MEDIUM", "HIGH"}:
            add(
                severity,
                f"scope-{scope.replace('/', '-').replace(':', '-')}",
                f"Scope requested: {scope} — {info.get('technical', 'No technical description available.')}",
                info.get("plain_language", "This permission affects user privacy or account access.")
            )

    return findings


def build_plain_language_summary(req, catalog):
    scopes = req["scopes"]
    known_scopes = catalog.get("scopes", {})

    if not scopes:
        return "This request does not list any OAuth scopes."

    explanations = []
    for scope in scopes:
        info = known_scopes.get(scope)
        if info:
            explanations.append(info.get("plain_language", scope))
        else:
            explanations.append(f"an unexplained permission named '{scope}'")

    joined = "; ".join(explanations)
    return f"This application is asking for permission to: {joined}."


def severity_rank(severity):
    order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    return order.get(severity, 0)


def risk_score(findings):
    score = 0
    for f in findings:
        if f["severity"] == "HIGH":
            score += 30
        elif f["severity"] == "MEDIUM":
            score += 15
        elif f["severity"] == "LOW":
            score += 5
    return min(score, 100)


def print_text_report(req, findings, summary):
    print("ConsentScope Report")
    print("===================")
    print()
    print("Authorization Request")
    print("---------------------")
    print(f"Client ID:       {req.get('client_id') or 'Not provided'}")
    print(f"Response type:   {req.get('response_type') or 'Not provided'}")
    print(f"Redirect URI:    {req.get('redirect_uri') or 'Not provided'}")
    print(f"Scopes:          {req.get('scope') or 'None'}")
    print()
    print("Findings")
    print("--------")

    if not findings:
        print("[OK] No major consent or trust issues were detected.")
    else:
        for finding in sorted(findings, key=lambda x: severity_rank(x["severity"]), reverse=True):
            print(f"[{finding['severity']}] {finding['message']}")
            print(f"      User meaning: {finding['plain_language']}")

    print()
    print("Plain-Language Summary")
    print("----------------------")
    print(summary)
    print()
    print(f"Risk score: {risk_score(findings)}/100")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze OAuth/OIDC authorization requests for privacy and trust risks."
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Authorization request URL or a path to a text file containing one."
    )
    parser.add_argument(
        "--catalog",
        default="rules/scope_catalog.json",
        help="Path to the scope catalog JSON file."
    )
    parser.add_argument(
        "--client-type",
        choices=["public", "confidential"],
        default="public",
        help="OAuth client type. Default: public."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON output instead of a text report."
    )
    parser.add_argument(
        "--output",
        help="Optional path to save JSON output."
    )

    args = parser.parse_args()

    raw_url = read_input(args.url)
    catalog = load_scope_catalog(args.catalog)
    req = parse_authorization_request(raw_url)
    findings = analyze_request(req, catalog, args.client_type)
    summary = build_plain_language_summary(req, catalog)

    result = {
        "tool": "ConsentScope",
        "client_type": args.client_type,
        "request": req,
        "findings": findings,
        "plain_language_summary": summary,
        "risk_score": risk_score(findings),
    }

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"Saved JSON report to {args.output}")
        return

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_text_report(req, findings, summary)


if __name__ == "__main__":
    main()
