#!/usr/bin/env python3
"""evm-bounty-guard: Static security scanner for Solidity smart contracts."""
import argparse, json, pathlib, re, sys
from dataclasses import dataclass, asdict

@dataclass
class Finding:
    rule_id: str
    severity: str
    file: str
    line: int
    title: str
    snippet: str

RULES = [
    ("EBG-001", "CRITICAL", "ERC-223 tokenReceived callback without nonReentrant modifier",
     re.compile(r"function\s+tokenReceived\s*\([^)]*\)\s*(?:external|public)(?![^{]*nonReentrant)")),
    ("EBG-002", "HIGH", "Low-level .call() without return-data boolean decoding check",
     re.compile(r"\.call\s*\(\s*abi\.encodeWithSelector\s*\([^)]*transfer")),
    ("EBG-003", "HIGH", "Public/external sweep or rescue function without access control",
     re.compile(r"function\s+(?:sweepToken|rescueERC20|unwrapWETH9)\s*\([^)]*\)\s*(?:external|public)(?![^{]*only)")),
    ("EBG-004", "MEDIUM", "Hardcoded POOL_INIT_CODE_HASH constant (verify against deployed factory)",
     re.compile(r"POOL_INIT_CODE_HASH\s*=\s*0x[0-9a-fA-F]{64}")),
    ("EBG-005", "MEDIUM", "collect() / withdraw() missing recipient != address(0) validation",
     re.compile(r"function\s+collect\s*\([^)]*\)\s*external")),
]

def scan_file(path: pathlib.Path) -> list[Finding]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    findings = []
    for rule_id, sev, title, pat in RULES:
        for m in pat.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            snippet = m.group(0).strip().replace("\n", " ")[:120]
            findings.append(Finding(rule_id, sev, str(path), line_no, title, snippet))
    return findings

def main():
    ap = argparse.ArgumentParser(description="Scan Solidity files for DeFi & ERC-20/223 vulnerabilities.")
    ap.add_argument("target", help="File or directory to scan")
    ap.add_argument("--json", action="store_true", help="Emit JSON output")
    args = ap.parse_args()
    root = pathlib.Path(args.target)
    files = [root] if root.is_file() else list(root.rglob("*.sol"))
    all_findings = []
    for f in files:
        all_findings.extend(scan_file(f))
    if args.json:
        print(json.dumps([asdict(x) for x in all_findings], indent=2))
    else:
        for fd in all_findings:
            print(f"[{fd.severity}] {fd.rule_id} {fd.file}:{fd.line} - {fd.title}\n  -> {fd.snippet}")
        print(f"\nScanned {len(files)} Solidity file(s), found {len(all_findings)} issue(s).")

if __name__ == "__main__":
    main()
