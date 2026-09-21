# SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
#
# SPDX-License-Identifier: Apache-2.0

"""QW-C-SYS-350: report drift between .github/settings.yml and the live repository.

Only the keys declared in settings.yml are compared, except for keyed lists
(rulesets, rules, status checks), where an entry present live but absent from
the file is drift too.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

SETTINGS_FILE = Path(".github/settings.yml")
LIST_KEYS = ("name", "type", "context")


class GitHubError(RuntimeError):
    pass


def main() -> int:
    desired = yaml.safe_load(SETTINGS_FILE.read_text(encoding="utf-8"))
    drift = find_drift(desired, fetch_live(repository_name()))
    for line in drift:
        print(f"drift: {line}")
    print(f"{len(drift)} setting(s) drifted" if drift else "no drift")
    return 1 if drift else 0


def find_drift(desired, live, path="") -> list[str]:
    if isinstance(desired, dict):
        return _dict_drift(desired, live, path)
    if isinstance(desired, list):
        return _list_drift(desired, live, path)
    if desired != live:
        return [f"{path}: expected {desired!r}, found {live!r}"]
    return []


def _dict_drift(desired: dict, live, path: str) -> list[str]:
    if not isinstance(live, dict):
        return [f"{path}: expected a mapping, found {live!r}"]
    drift = []
    for key, value in desired.items():
        child = f"{path}.{key}" if path else key
        if key not in live:
            drift.append(f"{child}: missing")
        else:
            drift.extend(find_drift(value, live[key], child))
    return drift


def _list_drift(desired: list, live, path: str) -> list[str]:
    if not isinstance(live, list):
        return [f"{path}: expected a list, found {live!r}"]
    key = _list_key(desired) or _list_key(live)
    if key is None:
        return _plain_list_drift(desired, live, path)
    return _keyed_list_drift(_index(desired, key), _index(live, key), path)


def _list_key(items: list):
    for key in LIST_KEYS:
        if items and all(isinstance(item, dict) and key in item for item in items):
            return key
    return None


def _index(items: list, key: str) -> dict:
    return {item[key]: item for item in items if isinstance(item, dict) and key in item}


def _keyed_list_drift(desired: dict, live: dict, path: str) -> list[str]:
    drift = [f"{path}[{name}]: present live, not declared" for name in live.keys() - desired.keys()]
    for name, item in desired.items():
        if name not in live:
            drift.append(f"{path}[{name}]: missing")
        else:
            drift.extend(find_drift(item, live[name], f"{path}[{name}]"))
    return sorted(drift)


def _plain_list_drift(desired: list, live: list, path: str) -> list[str]:
    if sorted(map(json.dumps, desired)) != sorted(map(json.dumps, live)):
        return [f"{path}: expected {desired!r}, found {live!r}"]
    return []


def repository_name() -> str:
    return os.environ.get("GITHUB_REPOSITORY") or gh("repo", "view", "--json", "nameWithOwner")["nameWithOwner"]


def fetch_live(repo: str) -> dict:
    return {
        "repository": _live_repository(repo),
        "actions": gh("api", f"repos/{repo}/actions/permissions/workflow"),
        "rulesets": [gh("api", f"repos/{repo}/rulesets/{summary['id']}") for summary in gh("api", f"repos/{repo}/rulesets")],
    }


def _live_repository(repo: str) -> dict:
    live = gh("api", f"repos/{repo}") | _merge_settings(repo)
    live["enable_vulnerability_alerts"] = _endpoint_exists(f"repos/{repo}/vulnerability-alerts")
    live["enable_automated_security_fixes"] = gh("api", f"repos/{repo}/automated-security-fixes")["enabled"]
    live["private_vulnerability_reporting"] = gh("api", f"repos/{repo}/private-vulnerability-reporting")["enabled"]
    return live


# The REST API omits these fields for read-only tokens; GraphQL does not.
MERGE_SETTINGS_QUERY = """
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    allow_squash_merge: squashMergeAllowed
    allow_merge_commit: mergeCommitAllowed
    allow_rebase_merge: rebaseMergeAllowed
    allow_auto_merge: autoMergeAllowed
    delete_branch_on_merge: deleteBranchOnMerge
  }
}
"""


def _merge_settings(repo: str) -> dict:
    owner, name = repo.split("/")
    result = gh("api", "graphql", "-f", f"query={MERGE_SETTINGS_QUERY}", "-F", f"owner={owner}", "-F", f"name={name}")
    return result["data"]["repository"]


def _endpoint_exists(endpoint: str) -> bool:
    result = subprocess.run(["gh", "api", endpoint], capture_output=True, text=True, check=False)
    if result.returncode == 0:
        return True
    if "HTTP 404" in result.stderr:
        return False
    raise GitHubError(f"gh api {endpoint} failed: {result.stderr.strip()}")


def gh(*args: str):
    result = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise GitHubError(f"gh {' '.join(args)} failed: {result.stderr.strip()}")
    return json.loads(result.stdout or "null")


if __name__ == "__main__":
    sys.exit(main())
