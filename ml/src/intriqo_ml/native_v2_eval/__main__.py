"""CLI for controlled native-v2 corpus construction (never model training)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .build import build_corpus


def main() -> None:
    parser = argparse.ArgumentParser(description="Build controlled Intriqo native-v2 evaluation artifacts")
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build", help="replay captured PCAPs and write quality artifacts")
    build.add_argument("--experiment-manifest", type=Path, required=True)
    build.add_argument("--capture-manifest", type=Path, required=True)
    build.add_argument("--split-definition", type=Path, required=True)
    build.add_argument("--output-dir", type=Path, required=True)
    build.add_argument("--engine", type=Path)
    args = parser.parse_args()
    if args.command == "build":
        try:
            result = build_corpus(
                experiment_manifest_path=args.experiment_manifest,
                capture_manifest_path=args.capture_manifest,
                split_definition_path=args.split_definition,
                output_dir=args.output_dir,
                engine=args.engine,
            )
        except (OSError, ValueError, json.JSONDecodeError) as error:
            parser.exit(1, f"controlled native-v2 corpus build failed: {error}\n")
        print(json.dumps({"status": result["status"], "output_dir": str(args.output_dir)}))


if __name__ == "__main__":
    main()
