# Secret Hygiene

Scan a project for passwords and API keys left in files or past changes. The report hides detected values so a team can investigate without repeating them. Built by Platino Labs.

Findings are possible exposures, not proof that a credential still works. This tool does not revoke or replace credentials automatically, and a clean scan cannot prove that no secret exists.

## Requirements

- Git
- Python 3.10 or newer
- [Gitleaks](https://github.com/gitleaks/gitleaks) installed and available on `PATH`

## Scan a repository

Run from a Git checkout:

```sh
bash run.sh
```

The script scans the working tree and Git history, with candidate values redacted. Exit codes:

- `0`: both scans completed without findings
- `1`: at least one scan found a candidate
- `2`: a scan could not be completed; this is **not** a clean result

A finding needs human review. Test fixtures and revoked credentials can appear, and a historic finding can remain after rotation.

## Cloudflare Workers helper

The Python command can pass a value from a local environment file to Wrangler as a Worker secret. It does not print the value or edit tracked configuration. The normal mode is a dry run; `--apply` performs a remote change. Review the Worker, environment, binding name, and local file before using `--apply`. This helper does not revoke or rotate the source credential, deploy the Worker, or update application code.

See the command options with:

```sh
python3 secret_hygiene.py --help
```

## Safe response to a finding

1. Identify the credential owner and the service using it; do not infer the provider from the token's shape.
2. Revoke the exposed credential and issue a replacement in the provider's official console.
3. Store the replacement in an approved local secret manager or environment, not in source, shell arguments, chat, or tickets.
4. Re-run the scan. Treat historical findings separately from whether a credential is still active.

## License

MIT. See [LICENSE](LICENSE).

## Want an audit?

[Contact Platino Labs on GitHub](https://github.com/alexisromtz-lab).

<!-- HUELLA-SECRETHYGIENE-PUBLIC-README-20261031 -->
