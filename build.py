import os
import sys
import glob
import json


def main(argv):
    target = argv[1]

    for s in ["tugraz"]:
        rules = []
        for path in sorted(glob.glob(s + "/*.json")):
            with open(path, "rb") as h:
                decoded = json.loads(h.read())
                rules.append({
                    "i": decoded["Identifier"],
                    "r": json.dumps(decoded),
                })
        os.makedirs(target, exist_ok=True)
        with open(os.path.join(target, s + ".json"), "w", encoding="utf-8") as h:
            h.write(json.dumps({"r": rules}, indent=2))


if __name__ == "__main__":
    main(sys.argv)