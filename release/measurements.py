#!/usr/bin/env python3
"""Turn the fingerprints file of a release lane into measurements.json.

    release/measurements.py --tag TAG --commit SHA --chain CHAIN --variant VARIANT \
        [--build-variant default|dvt] FINGERPRINTS > measurements.json

FINGERPRINTS is the fingerprints-<chain>[-dvt][-test].txt of
release/release-build.sh. Its variant, build_variant, commit and chain lines
must equal --variant, --build-variant (default: default), --commit and
--chain, so a test lane cannot be published as prod, a dvt lane not as a
default one, and no lane under another commit. A file without a
build_variant line is of a default lane (lanes from before DVT=1).

The setup_line of each image is the line an approver puts into a setup or a
locked update (governance/setuptext: allowed_image_measurements = KIND HEX...).
Only the standard library; no network.
"""

import argparse
import json
import re
import sys

HEX = {"nitro.PCR0": 96, "nitro.PCR1": 96, "nitro.PCR2": 96, "azure.cce_policy": 64,
       "nitro.runner": 64, "azure.runner": 64, "gcp.runner": 64}
# The value lines release/release-build.sh adds for the lane itself.
LANE = ("variant", "build_variant", "commit", "chain")


def read(path):
    values = {}
    with open(path, encoding="ascii") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, value = line.split(None, 1)
            values[name] = value
    for name, size in HEX.items():
        if not re.fullmatch("[0-9a-f]{%d}" % size, values.get(name, "")):
            sys.exit(f"measurements: {name} is missing or not {size} hex digits")
    for name in [n for n in values if n.startswith("parent.")]:
        if not re.fullmatch("[0-9a-f]{64}", values[name]):
            sys.exit(f"measurements: {name} is not 64 hex digits")
    for name in ("azure.image", "gcp.image"):
        if not re.fullmatch("sha256:[0-9a-f]{64}", values.get(name, "")):
            sys.exit(f"measurements: {name} is missing or not sha256:<64 hex>")
    return values


def main():
    ap = argparse.ArgumentParser()
    for a in ("--tag", "--commit", "--chain", "--variant"):
        ap.add_argument(a, required=True)
    ap.add_argument("--build-variant", default="default", choices=("default", "dvt"))
    ap.add_argument("fingerprints")
    args = ap.parse_args()
    v = read(args.fingerprints)
    v.setdefault("build_variant", "default")
    for name in LANE:
        if name not in v:
            sys.exit(f"measurements: no {name} line in {args.fingerprints} (not a release lane's file)")
        if v[name] != getattr(args, name):
            flag = name.replace("_", "-")
            sys.exit(f"measurements: --{flag} is {getattr(args, name)!r}, the lane was built with {v[name]!r}")
    pcrs = [v["nitro.PCR0"], v["nitro.PCR1"], v["nitro.PCR2"]]
    gcp = v["gcp.image"].removeprefix("sha256:")
    out = {
        "format": 1,
        "tag": args.tag,
        "commit": args.commit,
        "chain": args.chain,
        "variant": args.variant,
        "build_variant": args.build_variant,
        "images": {
            "nitro": {
                "arch": "aarch64",
                "pcr0": pcrs[0], "pcr1": pcrs[1], "pcr2": pcrs[2],
                "runner_sha256": v["nitro.runner"],
                "setup_line": "allowed_image_measurements = nitro " + " ".join("0x" + p for p in pcrs),
            },
            "azure": {
                "image_digest": v["azure.image"],
                "cce_policy_sha256": v["azure.cce_policy"],
                "runner_sha256": v["azure.runner"],
                "setup_line": "allowed_image_measurements = azure 0x" + v["azure.cce_policy"],
            },
            "gcp": {
                "image_digest": v["gcp.image"],
                "runner_sha256": v["gcp.runner"],
                "setup_line": "allowed_image_measurements = gcp 0x" + gcp,
            },
        },
        "parent_tools_sha256": {
            k.split(".", 1)[1]: v[k] for k in sorted(v) if k.startswith("parent.")
        },
    }
    json.dump(out, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
