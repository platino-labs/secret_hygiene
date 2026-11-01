#!/usr/bin/env python3
"""Safely transfer a local .env value into a Cloudflare Worker secret."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SECRET_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,254}$")
_ENVIRONMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$")
_CONFIG_NAMES = ("wrangler.toml", "wrangler.json", "wrangler.jsonc")


def read_env_value(env_file: Path, name: str) -> str:
    if not _ENV_NAME.fullmatch(name):
        raise ValueError("invalid source variable name")
    if env_file.is_symlink() or not env_file.is_file():
        raise ValueError("env file must be a regular, non-symlink file")

    values: dict[str, str] = {}
    for number, raw_line in enumerate(env_file.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, raw_value = line.partition("=")
        if not separator or not _ENV_NAME.fullmatch(key.strip()):
            raise ValueError(f"invalid .env syntax at line {number}")
        key = key.strip()
        if key in values:
            raise ValueError(f"duplicate .env variable at line {number}")
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if not value:
            raise ValueError(f"empty .env variable at line {number}")
        values[key] = value

    if name not in values:
        raise ValueError("requested source variable is absent from .env")
    return values[name]


def inject_cloudflare_secret(args: argparse.Namespace) -> int:
    if not _SECRET_NAME.fullmatch(args.secret_name):
        print("ERROR: invalid destination secret name")
        return 2
    if not _ENVIRONMENT.fullmatch(args.environment):
        print("ERROR: invalid Wrangler environment name")
        return 2

    worker_dir = args.worker_dir.resolve()
    if args.config.is_symlink():
        print("ERROR: Wrangler config must not be a symlink")
        return 2
    config = args.config.resolve()
    if not worker_dir.is_dir() or not config.is_file():
        print("ERROR: worker directory and explicit Wrangler config must exist")
        return 2
    try:
        config.relative_to(worker_dir)
    except ValueError:
        print("ERROR: Wrangler config must be inside the selected worker directory")
        return 2
    if config.name not in _CONFIG_NAMES:
        print("ERROR: config must be wrangler.toml, wrangler.json, or wrangler.jsonc")
        return 2

    try:
        value = read_env_value(args.env_file, args.source_variable)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"ERROR: {exc}")
        return 2

    command = [args.wrangler, "--config", str(config), "secret", "put", args.secret_name, "--env", args.environment]
    if not args.apply:
        print(
            "DRY RUN: no remote change; "
            f"worker_dir={worker_dir} config={config.name} environment={args.environment} "
            f"source={args.source_variable} destination={args.secret_name}"
        )
        return 0

    try:
        result = subprocess.run(
            command,
            cwd=worker_dir,
            input=value.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError:
        print("ERROR: Wrangler could not be started; secret value was not displayed")
        return 2

    if result.returncode:
        print(f"ERROR: Wrangler exited RC={result.returncode}; provider output suppressed")
        return 2
    print(
        f"UPDATED: secret={args.secret_name} environment={args.environment}; "
        "value not displayed or written to a tracked file"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Credential hygiene helpers; secret values are never printed")
    subparsers = parser.add_subparsers(dest="command", required=True)
    inject = subparsers.add_parser(
        "inject-cloudflare-secret",
        help="pipe one .env value to Wrangler; dry-run unless --apply is supplied",
    )
    inject.add_argument("--env-file", type=Path, required=True)
    inject.add_argument("--source-variable", required=True)
    inject.add_argument("--secret-name", required=True)
    inject.add_argument("--worker-dir", type=Path, required=True)
    inject.add_argument("--config", type=Path, required=True, help="explicit Wrangler config inside --worker-dir")
    inject.add_argument("--environment", required=True)
    inject.add_argument("--wrangler", default="wrangler")
    inject.add_argument("--apply", action="store_true", help="perform the remote secret update")
    return parser


def main() -> int:
    if sys.version_info < (3, 10):
        print("ERROR: Python 3.10 or newer is required")
        return 2
    args = build_parser().parse_args()
    if args.command == "inject-cloudflare-secret":
        return inject_cloudflare_secret(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

# HUELLA_SECRET_HYGIENE_TOOL_FINAL_20261031
