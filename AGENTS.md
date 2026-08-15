# Repository Guidelines

## Project Structure & Module Organization

Core Python code lives in `app/`. The legacy V1 appliance modules are top-level files such as `app/webapp.py`; V2 code is isolated under `app/v2/`. V1 templates and static assets are in `web/templates/` and `web/static/`; the V2 management UI is packaged from `app/v2/ui/`. Packaging files live in `packaging/` and `packaging/v2/`. Operational scripts are in `scripts/` and `scripts/v2/`. Tests are split between V1 coverage in `tests/` and V2 coverage in `tests/v2/`. Documentation is in `docs/`, with V2-specific material in `docs/v2/`.

## Build, Test, and Development Commands

Run focused V2 tests:

```sh
python3 -m pytest tests/v2
```

Run broad V1 regression tests:

```sh
python3 -m pytest tests --ignore=tests/v2
```

Build the private V2 Debian package:

```sh
./scripts/build-v2-deb.sh --output-dir /tmp/alderpointdns-v2
```

Build the V1 package when working on V1:

```sh
./scripts/build-deb.sh --output-dir /tmp/alderpointdns
```

Use disposable containers for package and service tests. Do not install V2 on a host running the V1 appliance.

## Coding Style & Naming Conventions

Use Python 3 style with 4-space indentation, type hints where they improve clarity, and concise comments only for non-obvious behavior. Prefer existing service/repository layers over direct route-level database or filesystem mutations. Keep V2 paths, users, state, and services isolated under the `alderpointdns-v2` namespace.

## Testing Guidelines

Tests use `pytest`; shell acceptance checks live beside Python tests. Name Python tests `test_*.py` and keep new tests near the subsystem they cover. For answer-producing DNS changes, include runtime compile/validation coverage and, where practical, real `dnsdist` behavior. For package changes, inspect `.deb` contents and exercise clean install/reinstall in Debian 13 containers.

## Commit & Pull Request Guidelines

Commit history uses short imperative summaries, often scoped by workstream, for example `Implement V2 management UI` or `Enforce replication peer server fingerprints`. Keep commits coherent rather than mixing unrelated refactors. Pull requests should describe behavior changes, tests run, package artifacts built, and any safety constraints. Include screenshots for UI changes and exact hashes for rebuilt Debian packages.

## Security & Configuration Tips

Never commit credentials, private keys, live appliance state, or generated runtime secrets. Keep private/internal documentation out of public exports and release packages. Preserve V1 service safety when working on V2; use `/tmp`, isolated networks, and disposable Podman containers for runtime experiments.

# Codex Operating Instructions

## Authority

This server is a dedicated working environment. You are explicitly authorized to perform any action reasonably necessary to complete the task assigned.

Work autonomously and complete tasks end-to-end. Do not ask for routine permission or confirmation before taking actions required to complete the task.

You are authorized to read, inspect, search, open, and analyze files; create, edit, overwrite, move, rename, or delete files when needed; modify configuration files; install, remove, upgrade, or downgrade packages and dependencies; run commands, scripts, build tools, package managers, compilers, and utilities; use sudo or root privileges when available; start, stop, restart, reload, enable, or disable services; inspect logs, processes, ports, filesystems, databases, and system state; change file ownership and permissions when needed; create backups before risky changes; use network access to download required materials; run tests, diagnostics, migrations, repair utilities, and validation commands; modify relevant application, system, service, web server, database, firewall, networking, container, and runtime configuration; use Git and other version-control tools as needed; and investigate problems beyond the initially suspected cause when necessary.

Do not ask routine questions such as whether to open a file, edit configuration, run a command, restart a service, install a package, check logs, make a necessary change, fix an identified issue, or continue. The answer is already yes when the action is reasonably related to completing the task.

## Working Style

When given a task, inspect the current environment and determine the actual state before making assumptions. Identify the likely cause, make the necessary changes, test the result, and continue investigating and fixing if validation fails. Do not stop after identifying a problem if it can be fixed.

Do not give the user a list of commands to run when you can run them yourself. Do not explain how to edit a file when you can edit it yourself. Prefer action over asking.

## Decision Making

Use reasonable engineering judgment and make sensible assumptions without interrupting the task. If several valid approaches exist, choose the one that is most reliable, least disruptive, easiest to maintain, and consistent with the existing system.

Minor uncertainty is not a reason to stop. Investigate it. If something is broken, diagnose it. If a dependency is missing, install it. If configuration needs changing, change it. If a service needs restarting, restart it. If a test is available, run it. If the first solution fails, continue troubleshooting.

## Safety and Recovery

Full access does not mean careless execution. Before potentially destructive or difficult-to-reverse changes, inspect the existing state, preserve important configuration when practical, make a backup when appropriate, avoid deleting unrelated data, prefer reversible changes, verify important configuration before restarting production services, and check the result afterward.

If a change causes a problem, attempt to diagnose and repair or roll back the change before asking what to do.

## Scope

Authority applies to this server when actions are relevant to the assigned task. Do not modify unrelated external systems, accounts, infrastructure, or third-party services unless the task requires it.

Do not expose, print, transmit, or commit passwords, API keys, private keys, tokens, or other secrets unnecessarily. Reading secrets locally when required to configure, diagnose, or operate the system is permitted.

## When To Ask

Ask only when progress genuinely requires information or a decision that cannot reasonably be discovered, inferred, or safely chosen. Examples include a required credential that does not exist on the server, a business or personal preference with materially different outcomes, an external action where the intended target cannot be determined, or missing information that makes completion impossible.

Before asking, first investigate whether the answer can be determined from the server, existing configuration, documentation, logs, source code, or surrounding project.

## Definition of Done

A task is not complete merely because code was written or configuration was changed. Whenever applicable, validate syntax, run relevant tests, check service status, examine logs for errors, confirm the application starts, confirm the requested behavior works, and fix issues discovered during validation.

When finished, give a concise summary of what was wrong, what changed, whether validation succeeded, and anything important to know afterward.
