"""Shared validation, findings, suppressions and reporting for defensive tools."""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "0.1.0"
SEVERITIES = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO 8601 string with a timezone")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamps require a timezone")
    return result.astimezone(timezone.utc)


def object_value(value, label="input"):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def records(data, key, required=()):
    object_value(data)
    rows = data.get(key)
    if not isinstance(rows, list):
        raise ValueError(f"{key} must be an array")
    for index, row in enumerate(rows):
        object_value(row, f"{key}[{index}]")
        if any(field not in row for field in required):
            raise ValueError(f"{key}[{index}] is missing required fields: {', '.join(required)}")
    return rows


def text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def boolean(value, label):
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be boolean")
    return value


def number(value, label, minimum=0, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{label} must be a finite number")
    if value < minimum or (maximum is not None and value > maximum):
        raise ValueError(f"{label} is outside the permitted range")
    return value


def string_list(value, label):
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{label} must be an array of non-empty strings")
    return value


def setting(policy, key, default, minimum=0, maximum=None):
    return number(policy.get(key, default), f"policy.{key}", minimum, maximum)


def finding(rule, severity, resource, title, evidence, remediation, **extra):
    if severity not in SEVERITIES:
        raise ValueError("unknown finding severity")
    resource = str(resource)
    stable = json.dumps([TOOL, rule, resource, extra.get("subject", "")], ensure_ascii=False)
    result = {"rule": rule, "severity": severity, "resource": resource,
              "title": title, "evidence": evidence, "remediation": remediation,
              "fingerprint": hashlib.sha256(stable.encode()).hexdigest()[:24]}
    result.update(extra)
    return result


def unique_rows(rows, key):
    result = {}
    for row in rows:
        identifier = text(row[key], key)
        if identifier in result:
            raise ValueError(f"duplicate {key} in inventory")
        result[identifier] = row
    return result


def decode_json(content):
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("JSON contains a duplicate key")
            result[key] = value
        return result
    return json.loads(content, object_pairs_hook=reject_duplicates,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("non-finite JSON number")))


def load_json(path):
    if path.stat().st_size > 10 * 1024 * 1024:
        raise ValueError("JSON input exceeds the 10 MiB limit")
    return decode_json(path.read_text(encoding="utf-8-sig"))


def build_report(findings, suppressions=(), now=None):
    now = now or datetime.now(timezone.utc)
    active, suppressed = [], []
    fingerprints = set()
    for suppression in suppressions:
        object_value(suppression, "suppression")
        text(suppression.get("fingerprint"), "suppression fingerprint")
        text(suppression.get("reason"), "suppression reason")
        timestamp(suppression.get("expires"))
        if suppression["fingerprint"] in fingerprints:
            raise ValueError("duplicate suppression fingerprint")
        fingerprints.add(suppression["fingerprint"])
    known = {item["fingerprint"]: item for item in suppressions
             if timestamp(item["expires"]) > now}
    for item in findings:
        if item["fingerprint"] in known:
            suppressed.append({**item, "suppression_reason": known[item["fingerprint"]]["reason"]})
        else:
            active.append(item)
    active.sort(key=lambda item: (-SEVERITIES[item["severity"]], item["resource"], item["rule"], item["fingerprint"]))
    return {"tool": TOOL, "version": VERSION, "generated_at": now.isoformat(),
            "summary": dict(Counter(item["severity"] for item in active)),
            "findings": active, "suppressed": suppressed}


def sarif(report):
    rules = {item["rule"]: item["title"] for item in report["findings"]}
    results = []
    for item in report["findings"]:
        results.append({"ruleId": item["rule"],
                        "level": "error" if SEVERITIES[item["severity"]] >= 3 else "warning" if SEVERITIES[item["severity"]] >= 1 else "note",
                        "message": {"text": item["title"] + ". " + item["remediation"]},
                        "locations": [{"logicalLocations": [{"name": item["resource"]}]}],
                        "partialFingerprints": {"securityToolFingerprint/v1": item["fingerprint"]},
                        "properties": {"severity": item["severity"], "evidence": item["evidence"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": TOOL, "version": VERSION,
                       "rules": [{"id": key, "shortDescription": {"text": title}} for key, title in sorted(rules.items())]}},
                       "results": results}]}


def markdown(report):
    def escape(value):
        return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    lines = [f"# {TOOL} report", "", f"Version: {VERSION}. Findings: {len(report['findings'])}.", "",
             "| Severity | Resource | Finding | Recommended action |", "|---|---|---|---|"]
    for item in report["findings"]:
        lines.append("| " + " | ".join(escape(item[key]) for key in ("severity", "resource", "title", "remediation")) + " |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("input", nargs="?", type=Path, help="JSON inventory, event export or tool configuration")
    parser.add_argument("--demo", action="store_true", help="run the embedded synthetic example")
    parser.add_argument("--policy", type=Path, help="JSON object overriding documented defaults")
    parser.add_argument("--suppressions", type=Path, help="JSON array: fingerprint, reason, expires")
    parser.add_argument("--format", choices=["json", "sarif", "markdown"], default="json")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fail-on", choices=list(SEVERITIES), default="high")
    parser.add_argument("--now", help="timezone-aware ISO timestamp for reproducible reviews")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    if args.demo == bool(args.input):
        parser.error("provide exactly one of input or --demo")
    try:
        now = timestamp(args.now) if args.now else datetime.now(timezone.utc)
        data = object_value(json.loads(json.dumps(DEMO)) if args.demo else load_json(args.input))
        policy = object_value(load_json(args.policy), "policy") if args.policy else {}
        suppressions = load_json(args.suppressions) if args.suppressions else []
        if not isinstance(suppressions, list):
            raise ValueError("suppressions must be an array")
        report = build_report(audit(data, policy, now), suppressions, now)
        content = markdown(report) if args.format == "markdown" else json.dumps(sarif(report) if args.format == "sarif" else report, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            # Exclusive creation keeps earlier evidence from being overwritten.
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(content)
        else:
            print(content, end="")
        return int(any(SEVERITIES[item["severity"]] >= SEVERITIES[args.fail_on] for item in report["findings"]))
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        parser.exit(2, f"error: {type(exc).__name__}: {exc}\n")
import re

TOOL = "software-supply-chain-auditor"
DESCRIPTION = "Review a CycloneDX dependency graph against local advisories and integrity policies."
DEMO = {"bom": {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"bom-ref": "app"}},
                "components": [{"bom-ref": "app", "name": "synthetic-app", "version": "1.0.0", "purl": "pkg:generic/synthetic-app@1.0.0", "hashes": [{"alg": "SHA-256", "content": "0" * 64}], "licenses": [{"license": {"id": "MIT"}}]},
                               {"bom-ref": "library", "name": "synthetic-library", "version": "1.2.0", "purl": "pkg:generic/synthetic-library@1.2.0", "hashes": [], "licenses": [{"license": {"id": "AGPL-3.0-only"}}]}],
                "dependencies": [{"ref": "app", "dependsOn": ["library"]}, {"ref": "library", "dependsOn": []}]},
        "advisories": [{"id": "SYNTH-2026-001", "package": "pkg:generic/synthetic-library", "introduced": "1.0.0", "fixed": "2.0.0", "severity": "high", "known_exploited": True}]}


def release_version(value):
    if not isinstance(value, str) or re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,3}", value) is None:
        raise ValueError("only numeric release versions with at most four parts are supported")
    parts = tuple(int(part) for part in value.split("."))
    return parts + (0,) * (4 - len(parts))


def dependency_path(start, target, graph):
    queue, visited = deque([(start, [start])]), set()
    while queue:
        node, path = queue.popleft()
        if node == target:
            return path
        if node in visited:
            continue
        visited.add(node)
        queue.extend((child, path + [child]) for child in graph.get(node, []))
    return []


def audit(data, policy, now):
    bom = object_value(data.get("bom"), "bom")
    if bom.get("bomFormat") != "CycloneDX":
        raise ValueError("bomFormat must be CycloneDX")
    components = unique_rows(records(bom, "components", ("bom-ref", "name", "version", "purl")), "bom-ref")
    dependencies = unique_rows(records(bom, "dependencies", ("ref", "dependsOn")), "ref")
    graph = {}
    for identifier, dependency in dependencies.items():
        children = string_list(dependency["dependsOn"], "dependsOn")
        if identifier not in components or any(child not in components for child in children):
            raise ValueError("dependency references an unknown component")
        graph[identifier] = children
    start = bom.get("metadata", {}).get("component", {}).get("bom-ref")
    if start not in components:
        raise ValueError("metadata.component.bom-ref must identify an included application component")
    advisories = records(data, "advisories", ("id", "package", "introduced", "fixed", "severity", "known_exploited"))
    for advisory in advisories:
        if advisory["severity"] not in SEVERITIES:
            raise ValueError("unsupported advisory severity")
        boolean(advisory["known_exploited"], "known_exploited")
        lower, upper = release_version(advisory["introduced"]), release_version(advisory["fixed"])
        if lower >= upper:
            raise ValueError("advisory introduced must precede fixed")
    denied_licenses = string_list(policy.get("denied_licenses", ["AGPL-3.0-only"]), "denied_licenses")
    require_hash = boolean(policy.get("require_sha256", True), "require_sha256")
    result = []
    for identifier, component in components.items():
        path = dependency_path(start, identifier, graph)
        purl = text(component["purl"], "purl").split("?", 1)[0].split("#", 1)[0]
        package = purl.rsplit("@", 1)[0] if "@" in purl.rsplit("/", 1)[-1] else purl
        try:
            version = release_version(component["version"])
        except ValueError:
            result.append(finding("SBOM-VERSION-REVIEW", "medium", identifier, "Version requires a richer ecosystem comparator",
                                  {"version": component["version"]}, "Review prerelease and ecosystem-specific version ranges using an approved resolver."))
            version = None
        if version is not None:
            for advisory in advisories:
                if advisory["package"] == package and release_version(advisory["introduced"]) <= version < release_version(advisory["fixed"]):
                    severity = "critical" if advisory["known_exploited"] else advisory["severity"]
                    result.append(finding("SBOM-VULNERABLE-COMPONENT", severity, identifier, "Component matches a local vulnerability advisory",
                                          {"advisory": advisory["id"], "version": component["version"], "fixed": advisory["fixed"], "dependency_path": path, "reachable_from_app": bool(path)},
                                          "Validate advisory applicability and update the dependency through a tested change.", subject=advisory["id"]))
        hashes = component.get("hashes", [])
        if not isinstance(hashes, list):
            raise ValueError("component hashes must be an array")
        has_sha256 = any(isinstance(item, dict) and item.get("alg") == "SHA-256" and isinstance(item.get("content"), str) and re.fullmatch(r"[0-9a-fA-F]{64}", item["content"]) for item in hashes)
        if require_hash and not has_sha256:
            result.append(finding("SBOM-CHECKSUM-EVIDENCE", "medium", identifier, "SBOM lacks a valid SHA-256 checksum",
                                  {"dependency_path": path}, "Capture build artifact checksums and verify them against a trusted source."))
        licenses = component.get("licenses", [])
        if not isinstance(licenses, list):
            raise ValueError("licenses must be an array")
        for license_record in licenses:
            object_value(license_record, "license")
            license_id = license_record.get("license", {}).get("id")
            if license_id in denied_licenses:
                result.append(finding("SBOM-LICENSE-POLICY", "medium", identifier, "License requires policy review",
                                      {"license": license_id}, "Obtain the organization's approved license review; this tool is not legal advice.", subject=license_id))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
