#!/usr/bin/env python
# SPDX-License-Identifier: MIT
import argparse
import importlib
import logging
import os

monitor = importlib.import_module("drawpile-monitor")


def _to_verdict(b):
    return "OFFENSIVE" if b else "CLEAN"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Drawpile Monitor Profanity Checker",
        description="Interactively check what drawpile-monitor considers offensive",
    )
    parser.add_argument(
        "-c",
        "--config",
        help="Where to find the config file",
    )
    args = parser.parse_args()

    config = monitor.Config(args.config, test_profanity_only=True)
    monitor.init_profanity_checker(config.wordlist_path)
    monitor.init_is_offensive(config.min_offensive_probability)

    min_prob = config.min_offensive_probability
    try:
        while True:
            print()
            s = input("Enter string to check: ")
            bp = monitor.is_offensive_better_profanity(s)
            pc_prob = monitor.is_offensive_profanity_check(s)
            pc = pc_prob >= min_prob
            pc_comparison = ">=" if pc else "<"
            result = monitor.is_offensive(s)
            print(f"\tinput: {repr(s)}")
            print(f"\tword list checker: {_to_verdict(bp)}")
            print(
                f"\tprediction checker: {_to_verdict(pc)} "
                + f"({pc_prob * 100.0:.2f}% {pc_comparison} {min_prob * 100.0:.2f}%)"
            )
            print(f"\tfinal verdict: {_to_verdict(result)}")
    except EOFError:
        print()
        print()
