#!/usr/bin/env python3

import os
import sys
import glob
import json


DIR = os.path.dirname(os.path.realpath(__file__))

def main(argv):
    rulesets = os.path.join(DIR, "rulesets")
    for name in os.listdir(rulesets):
        source = os.path.join(rulesets, name)
        for path in sorted(glob.glob(source + "/**/*.json", recursive=True)):
            with open(path, "rb") as h:
                sorted_rules = json.dumps(json.loads(h.read()), sort_keys=True, indent=4)
            with open(path, "w", encoding="utf-8") as h:
                h.write(sorted_rules)

if __name__ == "__main__":
    main(sys.argv)