#!/usr/bin/env python3
"""Regenerate system_prompt.txt from an external source system prompt.

Pulls the system prompt sent to this agent (or any source you point it at) and
writes it to system_prompt.txt, the file both checkers always send.

The bottom of a real Hermes system prompt carries four live values:

    Conversation started: Monday, August 24, 2026 (PDT, UTC-07:00)
    Model: <model>
    Provider: <provider>
    Platform: <platform>

Those are real metadata that we must NOT ship. This tool rewrites each of those
four lines back to its {{PLACEHOLDER}} token so the committed fixture never
leaks the real date/model/provider/platform.

Important: this only re-placeholders the four footer lines. Everything else in
the source is written verbatim — so if the source is your own real Hermes snap
shot, its PERSONAL sections (memory, user profile, skills, servers, etc.) will
be copied in too. You must manually re-personify/scrub those before pushing, or
use a source that is already sanitized.

Usage:
  python3 update_system_prompt.py                 # auto-locate latest Hermes snapshot
  python3 update_system_prompt.py -p custom.txt   # raw text prompt
  python3 update_system_prompt.py -p dump.json    # Hermes request-dump JSON
  python3 update_system_prompt.py --dry-run       # print result, don't write
  python3 update_system_prompt.py --out /tmp/sp.txt

Stdlib only.
"""

import argparse
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# Footer lines -> placeholder token. `.` must be anchored; these match the line
# header plus anything after it. Order matters (Model/Provider/Platform).
PLACEHOLDERS = [
    (re.compile(r"^Conversation started:.*$", re.MULTILINE),
     "Conversation started: {{CONVERSATION_STARTED}}"),
    (re.compile(r"^Model:.*$", re.MULTILINE), "Model: {{MODEL}}"),
    (re.compile(r"^Provider:.*$", re.MULTILINE), "Provider: {{PROVIDER}}"),
    (re.compile(r"^Platform:.*$", re.MULTILINE), "Platform: {{PLATFORM}}"),
]

DEFAULT_OUT = os.path.join(HERE, "system_prompt.txt")
SNAPSHOT_GLOB = os.path.expanduser("~/.hermes/sessions/request_dump_*.json")


def find_latest_snapshot():
    files = sorted(glob.glob(SNAPSHOT_GLOB), key=os.path.getmtime, reverse=True)
    if not files:
        sys.exit(f"no Hermes snapshots found at {SNAPSHOT_GLOB}")
    return files[0]


def extract_system(prompt_text, source_path):
    """Return (system_prompt, source_label)."""

    # A Hermes request dump is a JSON object with request.body.messages.
    if source_path.lower().endswith((".json",)):
        try:
            d = json.loads(prompt_text)
            body = d["request"]["body"]
            for m in body["messages"]:
                if m.get("role") == "system":
                    content = m["content"]
                    if isinstance(content, list):
                        content = "".join(
                            (p.get("text") or p.get("content") or "")
                            for p in content)
                    return content, f"snapshot {os.path.basename(source_path)}"
        except (KeyError, TypeError, ValueError):
            pass  # not a request dump — treat as raw prompt text

    return prompt_text, os.path.basename(source_path)


def placeholder_footer(text):
    """Rewrite the four footer lines to {{TOKEN}}, returning (new_text, report)."""
    lines = text.splitlines(keepends=True)
    seen = {}
    for i, line in enumerate(lines):
        for rx, replacement in PLACEHOLDERS:
            if rx.match(line):
                stripped = line.rstrip("\n")
                if "{{" in stripped:
                    seen[rx.pattern] = f"already placeholder: {stripped}"
                else:
                    lines[i] = replacement + "\n" if line.endswith("\n") \
                        else replacement
                    seen[rx.pattern] = f"replaced: {stripped}"
                break
    report = []
    ok = True
    for rx, replacement in PLACEHOLDERS:
        token = replacement.split("{{")[1].split("}}")[0]
        status = seen.get(rx.pattern)
        if status is None:
            report.append(f"  MISSING line for {token}: not found — leaving as-is")
            ok = False
        else:
            report.append(f"  {status}")
    return "".join(lines), report, ok


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("-p", "--prompt", metavar="PATH",
                    help="source system-prompt file (raw text or Hermes request "
                         "dump JSON); default: latest ~/.hermes snapshot")
    ap.add_argument("--out", metavar="PATH", default=DEFAULT_OUT,
                    help=f"destination file (default: {DEFAULT_OUT})")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the result to stdout without writing")
    args = ap.parse_args()

    source = args.prompt or find_latest_snapshot()
    with open(source) as f:
        raw = f.read()
    system_prompt, label = extract_system(raw, source)

    updated, report, ok = placeholder_footer(system_prompt)

    print(f"source : {label}")
    print("footer :")
    for line in report:
        print(line)
    if not ok:
        print("WARNING: some footer placeholder lines are missing from the "
              "source prompt. Double-check before committing.")

    if args.dry_run:
        print("\n--- RESULT (dry run, not written) ---")
        sys.stdout.write(updated)
        return

    with open(args.out, "w") as f:
        f.write(updated)
    print(f"\nwrote  : {args.out}")


if __name__ == "__main__":
    main()
