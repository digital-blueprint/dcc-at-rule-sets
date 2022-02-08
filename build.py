#!/usr/bin/env python3

import os
import sys
import glob
import json


DIR = os.path.dirname(os.path.realpath(__file__))

def main(argv):
    target = os.path.abspath(argv[1])

    rulesets = os.path.join(DIR, "rulesets")
    for name in os.listdir(rulesets):
        source = os.path.join(rulesets, name)
        rules = []
        for path in sorted(glob.glob(source + "/**/*.json", recursive=True)):
            with open(path, "rb") as h:
                decoded = json.loads(h.read())
                rules.append({
                    "i": decoded["Identifier"],
                    "r": json.dumps(decoded),
                })
        os.makedirs(target, exist_ok=True)
        with open(os.path.join(target, name + ".json"), "w", encoding="utf-8") as h:
            h.write(json.dumps({"r": rules}, indent=2))


if __name__ == "__main__":
    main(sys.argv)