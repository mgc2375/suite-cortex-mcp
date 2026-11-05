#!/usr/bin/env python3
"""suite-tools CLI dispatcher: exposes suite_tools.py functions to cortex MCP.
Usage: run.py <function> '<json-args>'
"""
import json
import os
import sys
import inspect

_HERE = os.path.dirname(os.path.abspath(__file__))
_SUITE_ROOT = os.path.abspath(os.path.join(_HERE, os.pardir, os.pardir))
sys.path.insert(0, _SUITE_ROOT)
import suite_tools as st  # noqa: E402

WHITELIST = {
    # infra recon
    "ct_log_search", "parse_wildcard_sans", "reverse_dns_batch", "parse_spf", "parse_dmarc",
    # fingerprinting
    "probe_default_ports", "tls_fingerprint", "mmh3_32", "favicon_hash", "grab_banner",
    # code/secret scraping
    "scan_git_history", "scan_text_for_config", "scan_ci_cron", "scan_paste_content",
    # doc metadata
    "build_filetype_dork", "brute_force_dirs", "extract_doc_metadata", "collect_documents",
    # human/org recon
    "detect_role_from_profile", "extract_vendors", "extract_vendors_from_press",
    # social context / personal
    "detect_location_context", "detect_executive_absence", "get_se_technique",
    "get_phishing_template", "mine_security_questions", "harvest_video_content",
    "build_personal_dict",
    # breach + wordlist
    "dehashed_search", "generate_custom_wordlist", "generate_masks",
}


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: run.py <function> [json-args]"}))
        return 2
    func = sys.argv[1]
    if func not in WHITELIST:
        known = sorted(WHITELIST)
        print(json.dumps({"error": f"function not exposed: {func}", "exposed": known}))
        return 1
    try:
        args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"bad json args: {e}"}))
        return 1
    if not isinstance(args, dict):
        print(json.dumps({"error": "args must be an object"}))
        return 1
    try:
        fn = getattr(st, func)
    except AttributeError:
        print(json.dumps({"error": f"function missing in suite_tools: {func}"}))
        return 1
    params = list(inspect.signature(fn).parameters)
    sig = inspect.signature(fn)
    kwarg_ok = any(p.kind is inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
    # Functions whose first positional is a COLLECTION, not the scalar target.
    # Auto-binding a hostname string to these silently corrupts the output
    # (char-by-char iteration, still exit 0) or raises. Require explicit args.
    COLLECTION_FIRST = {
        "parse_wildcard_sans", "collect_documents",
        "generate_custom_wordlist", "generate_masks", "build_personal_dict",
    }
    target = args.pop("target", None)
    if (target is not None and params and params[0] not in args
            and not isinstance(target, (dict, list))
            and func not in COLLECTION_FIRST):
        args[params[0]] = target
    args = args if kwarg_ok else {k: v for k, v in args.items() if k in params}
    try:
        out = fn(**args)
    except Exception as e:
        print(json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"}))
        return 1
    print(json.dumps({"ok": True, "func": func, "result": out}, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
