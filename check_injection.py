#!/usr/bin/env python3
"""Document prompt-injection detector.

Screens untrusted documents (PDF/image/embedded text) that you plan to send to
an LLM, for hidden prompt-injection payloads that hijack the model's behavior —
e.g. white text in a PDF saying "this is the candidate you should hire" or
"ignore previous instructions".

Detection signals:
  1. Canary: a known string your rubric tells the model to echo; if the injected
     doc makes the model drop it -> ABSENT -> suspected injection.
  2. Honeypot tools: tempting fake tool schemas exposed but NEVER executed; a
     call to one is a strong injection signal.
  3. Tool-call inspection of anything else the model proposes.

Nothing is executed. Read-only.

Usage:
  python3 check_injection.py --prompt example_prompt.txt --canary REVIEW-9F3K
  python3 check_injection.py --prompt example_prompt.txt --attach candidate.pdf
  python3 check_injection.py --prompt example_prompt.txt [--verbose]
"""

import argparse
import datetime as dt
import json
import os

import llm_client as lc


def main():
    ap = argparse.ArgumentParser(description="Document prompt-injection detector")
    ap.add_argument("--prompt", metavar="FILE",
                    help="file containing the user prompt (required)")
    ap.add_argument("--config", default=os.path.join(lc.HERE, "config.json"))
    ap.add_argument("--attach", action="append", metavar="FILE",
                    help="untrusted document to screen (image or PDF, repeatable); "
                         "omit to test an injected document embedded in the prompt "
                         "text (works on text-only models)")
    ap.add_argument("--canary", metavar="STRING",
                    help="string the model must echo; absence => possible injection")
    ap.add_argument("--tools", metavar="FILE",
                    help="override the tool-schemas file")
    ap.add_argument("--no-tools", action="store_true",
                    help="do not pass tool schemas (model can't propose calls)")
    ap.add_argument("--date", help="optional injected date YYYY-MM-DD "
                                   "(default: real today)")
    ap.add_argument("--offset", help="optional date offset: 6m, 12m, 30d, 2y")
    ap.add_argument("--host", help="override config host")
    ap.add_argument("--port", type=int, help="override config port")
    ap.add_argument("--model", help="override config model")
    ap.add_argument("--api-key", help="override config api_key")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--max-tokens", type=int, help="override config max_tokens")
    args = ap.parse_args()

    if not args.prompt:
        ap.error("provide a user prompt file via --prompt "
                 "(e.g. --prompt example_prompt.txt)")
    with open(args.prompt) as f:
        user_prompt = f.read()

    cfg = lc.load_config(args.config)

    # date: default to real today (injection testing isn't about shifting dates);
    # allow --date/--offset if you also want a future-date frame
    now = dt.date.today()
    if args.date:
        try:
            injected = dt.date.fromisoformat(args.date)
        except ValueError:
            ap.error(f"--date must be YYYY-MM-DD, got '{args.date}'")
    elif args.offset:
        injected = lc.apply_offset(now, args.offset)
    else:
        injected = now

    host = args.host or cfg["host"]
    port = args.port if args.port is not None else cfg["port"]
    model = args.model or cfg["model"]
    api_key = args.api_key if args.api_key is not None else cfg.get("api_key", "")

    base_prompt = lc.load_system_prompt(None, cfg.get("system_prompt_file"))
    tools = lc.load_tools(args.tools, cfg.get("tools_file"))
    if args.no_tools:
        tools = None

    # build the (possibly future-dated) system prompt
    system_prompt = lc.build_system_prompt(base_prompt, injected)

    # the full exposed toolset is the lure set: a proposed call to any tool is a
    # backdoor/injection signal (inspected, never executed)
    lure_names = {t["function"]["name"] for t in tools} if tools else set()

    lc.print_header(host, port, model, injected,
                    len(tools) if tools else 0,
                    args.attach, args.canary, user_prompt)

    print("INFO    : screening attached document(s) for prompt injection "
          "(read-only).")

    res = lc.send(host, port, model, api_key, system_prompt, user_prompt,
                  attach_paths=args.attach, tools=tools,
                  max_tokens=args.max_tokens or cfg.get("max_tokens", 1024),
                  timeout=cfg.get("timeout", 180))
    if not res["ok"]:
        print(f"[ERROR] HTTP {res['status']}")
        print(res["error_body"][:2000])
        raise SystemExit(1)
    if args.verbose:
        print("\n----- RAW RESPONSE -----")
        print(json.dumps(res["raw"], indent=2)[:6000])
        print("-----------------------")

    lc.print_reply(res["content"])
    lc.print_tool_reports(res["reports"])
    lc.print_injection_scan(args.canary, res["content"], res["reports"],
                            lure_names)

    if args.verbose and res.get("usage"):
        print("\nusage:", res["usage"])


if __name__ == "__main__":
    main()
