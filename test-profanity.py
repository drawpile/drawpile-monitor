#!/usr/bin/env python
# SPDX-License-Identifier: MIT
import argparse
import importlib
import logging
import os

monitor = importlib.import_module("drawpile-monitor")


def _to_verdict(b):
    return "OFFENSIVE" if b else "ALLOWED"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Drawpile Monitor Profanity Checker",
        description="Interactively check what drawpile-monitor considers offensive",
    )
    parser.add_argument(
        "-c",
        "--config",
        help="Path to config file or http(s) URL to config endpoint, "
        + "falls back to the DRAWPILE_MONITOR_CONFIG environment variable "
        + "or config.ini in the script's directory otherwise",
    )
    args = parser.parse_args()

    config = monitor.Config(
        args.config or os.environ.get("DRAWPILE_MONITOR_CONFIG"),
        test_profanity_only=True,
    )
    monitor.init_wordlist_checker(config.wordlist_path, config.nsfm_wordlist_path)
    monitor.init_filter_allowed(config.allowlist_path)
    monitor.init_is_offensive(config.min_offensive_probability)
    monitor.init_is_offensive_nsfm(config.nsfm_wordlist_path)
    monitor.init_is_offensive_silent(config.silent_wordlist_path)

    min_prob = config.min_offensive_probability
    try:
        while True:
            print()
            s = input("Enter string to check: ")
            filtered = monitor.filter_allowed(s)
            wl = monitor.is_offensive_wordlist(filtered)
            pc_prob = monitor.is_offensive_profanity_check(filtered)
            pc = pc_prob >= min_prob
            pc_comparison = ">=" if pc else "<"
            result = monitor.is_offensive(s)
            nsfm_result = monitor.is_offensive_nsfm(s)
            print(f"\tinput: {repr(s)}")
            print(f"\tafter applying allowlist: {repr(filtered)}")
            print(f"\tword list checker: {_to_verdict(wl)}")
            print(
                f"\tprediction checker: {_to_verdict(pc)} "
                + f"({pc_prob * 100.0:.2f}% {pc_comparison} {min_prob * 100.0:.2f}%)"
            )
            print(f"\tregular verdict: {_to_verdict(result)}")
            print(f"\tnsfm verdict: {_to_verdict(nsfm_result)}")
            print(f"\tsilent notification: {monitor.is_offensive_silent(s)}")
    except EOFError:
        print()
        print()
