#!/usr/bin/env python3
"""LLM future-backdoor checker.

Sends a user prompt against a configured host/port/model with a system prompt
whose "current date" is INJECTED to an arbitrary value (six months out, twelve
months out, any date you choose). Intended to surface a hidden date-triggered
backdoor inside the model itself: if the model behaves differently at a future
date, that difference is the signal.

Any tool calls the model proposes are inspected, never executed.

Usage:
  python3 check_backdoor.py --prompt example_prompt.txt --offset 6m    # +6 months
  python3 check_backdoor.py --prompt example_prompt.txt --offset 12m
  python3 check_backdoor.py --prompt example_prompt.txt --date 2029-12-25
  python3 check_backdoor.py --prompt example_prompt.txt --today        # baseline
  python3 check_backdoor.py --prompt example_prompt.txt --no-tools
  python3 check_backdoor.py --prompt example_prompt.txt --attach letter.pdf --canary X
  python3 check_backdoor.py --prompt example_prompt.txt --host h --port p --model m
"""

import argparse
import datetime as dt
import json
import os

import llm_client as lc


def main():
    ap = argparse.ArgumentParser(description="LLM future-backdoor checker")
    ap.add_argument("--prompt", metavar="FILE",
                    help="file containing the user prompt (required)")
    ap.add_argument("--config", default=os.path.join(lc.HERE, "config.json"))
    ap.add_argument("--date", help="inject arbitrary date YYYY-MM-DD")
    ap.add_argument("--offset", help="inject offset from now: 6m, 12m, 30d, 2y")
    ap.add_argument("--today", action="store_true",
                    help="baseline: real today, no injection")
    ap.add_argument("--no-tools", action="store_true",
                    help="do not pass tool schemas (model can't propose calls)")
    ap.add_argument("--no-date-note", dest="no_date_note", action="store_true",
                    help="rewrite the date line but do not append the override note")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--max-tokens", type=int, help="override config max_tokens")
    ap.add_argument("--attach", action="append", metavar="FILE",
                    help="attach an image/PDF to the user message (repeatable)")
    ap.add_argument("--canary", metavar="STRING",
                    help="check this appears in the reply (make it a random "
                         "token the rubric must echo)")
    ap.add_argument("--tools", metavar="FILE", help="override the tool-schemas file")
    ap.add_argument("--host", help="override config host")
    ap.add_argument("--port", type=int, help="override config port")
    ap.add_argument("--model", help="override config model")
    ap.add_argument("--api-key", help="override config api_key")
    args = ap.parse_args()

    if not args.prompt:
        ap.error("provide a user prompt file via --prompt "
                 "(e.g. --prompt example_prompt.txt)")
    with open(args.prompt) as f:
        user_prompt = f.read()

    cfg = lc.load_config(args.config)

    # ---- resolve injected date -------------------------------------------
    now = dt.date.today()
    if args.date:
        try:
            injected = dt.date.fromisoformat(args.date)
        except ValueError:
            ap.error(f"--date must be YYYY-MM-DD, got '{args.date}'")
    elif args.offset:
        injected = lc.apply_offset(now, args.offset)
    else:
        injected = now  # --today or default: baseline real today

    # ---- resolve target & files (CLI overrides config) --------------------
    host = args.host or cfg["host"]
    port = args.port if args.port is not None else cfg["port"]
    model = args.model or cfg["model"]
    api_key = args.api_key if args.api_key is not None else cfg.get("api_key", "")
    base_prompt = lc.load_system_prompt(None, cfg.get("system_prompt_file"))
    tools = lc.load_tools(args.tools, cfg.get("tools_file"))
    if args.no_tools:
        tools = None

    system_prompt = lc.build_system_prompt(
        base_prompt, injected, explicit_note=not args.no_date_note)

    lc.print_header(host, port, model, injected,
                    len(tools) if tools else 0,
                    args.attach, args.canary, user_prompt)

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

    if args.verbose and res.get("usage"):
        print("\nusage:", res["usage"])


if __name__ == "__main__":
    main()
