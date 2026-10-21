#!/usr/bin/env python3
"""Validate the deployment security contract after Compose normalization.

The repository intentionally does not ship a production Compose file.  This
checker is the gate that a deployment file must pass before it is used.  The
Compose CLI performs YAML interpolation and normalization; this script only
consumes its JSON output and never executes a service.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


SENSITIVE_ENV = re.compile(
    r"(?:^|[_-])(?:PASSWORD|TOKEN|PRIVATE[_-]?KEY|SECRET|API[_-]?KEY|KEY|CERT)(?:$|[_-])",
    re.IGNORECASE,
)
FILE_ENV = re.compile(
    r".*(?:PASSWORD|TOKEN|PRIVATE[_-]?KEY|SECRET|API[_-]?KEY|KEY|CERT)(?:_FILE|_PATH)$",
    re.IGNORECASE,
)
PEM_MARKER = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ED25519 )?(?:PRIVATE|PUBLIC) KEY-----")
FORBIDDEN_CAPS = {"SYS_ADMIN", "SYS_PTRACE", "NET_RAW", "SYS_MODULE", "DAC_READ_SEARCH"}
WORKER_CAPS = {"NET_ADMIN", "SETUID", "SETGID"}


def _as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _env_map(service: dict[str, Any]) -> dict[str, Any]:
    environment = service.get("environment", {})
    if isinstance(environment, dict):
        return {str(key): value for key, value in environment.items()}
    if isinstance(environment, list):
        result: dict[str, Any] = {}
        for entry in environment:
            if not isinstance(entry, str):
                continue
            key, separator, value = entry.partition("=")
            result[key] = value if separator else None
        return result
    return {}


def _network_names(service: dict[str, Any]) -> set[str]:
    networks = service.get("networks", {})
    if isinstance(networks, dict):
        return {str(name) for name in networks}
    if isinstance(networks, list):
        return {str(name) for name in networks}
    return set()


def _secret_names(service: dict[str, Any]) -> set[str]:
    secrets = service.get("secrets", [])
    names: set[str] = set()
    if isinstance(secrets, list):
        for item in secrets:
            if isinstance(item, str):
                names.add(item)
            elif isinstance(item, dict) and item.get("source"):
                names.add(str(item["source"]))
    elif isinstance(secrets, dict):
        names.update(str(name) for name in secrets)
    return names


def _secret_targets(service: dict[str, Any]) -> set[str]:
    secrets = service.get("secrets", [])
    targets: set[str] = set()
    if isinstance(secrets, list):
        for item in secrets:
            if isinstance(item, dict) and item.get("target"):
                targets.add(str(item["target"]))
    return targets


def _volume_for_target(service: dict[str, Any], target: str) -> dict[str, Any] | None:
    volumes = service.get("volumes", [])
    if not isinstance(volumes, list):
        return None
    for volume in volumes:
        if isinstance(volume, dict) and volume.get("target") == target:
            return volume
    return None


def _is_read_only(volume: dict[str, Any]) -> bool:
    if volume.get("read_only") is True:
        return True
    mode = str(volume.get("mode", ""))
    return "ro" in {part.strip().lower() for part in mode.split(",")}


def _is_writable(volume: dict[str, Any]) -> bool:
    return not _is_read_only(volume)


def _capability_name(value: Any) -> str:
    return str(value).strip().upper().removeprefix("CAP_")


def _published_ports(service: dict[str, Any]) -> list[dict[str, Any]]:
    ports = service.get("ports", [])
    if not isinstance(ports, list):
        return []
    return [port for port in ports if isinstance(port, dict)]


def _walk_true_keys(value: Any, key: str) -> bool:
    """Find a true host-namespace extension without interpreting arbitrary text."""
    if isinstance(value, dict):
        for name, child in value.items():
            if name.lower() == key.lower() and child is True:
                return True
            if _walk_true_keys(child, key):
                return True
    elif isinstance(value, list):
        return any(_walk_true_keys(child, key) for child in value)
    return False


def _check_common(service_name: str, service: dict[str, Any], errors: list[str]) -> None:
    for field in ("network_mode", "pid", "ipc", "uts"):
        value = str(service.get(field, "")).strip().lower()
        if field == "network_mode" and value:
            errors.append(f"{service_name}: network_mode is forbidden; use an explicit named network")
        elif value == "host":
            errors.append(f"{service_name}: {field}: host is forbidden")
    if _walk_true_keys(service, "hostNetwork"):
        errors.append(f"{service_name}: hostNetwork=true is forbidden")
    if service.get("privileged") is True:
        errors.append(f"{service_name}: privileged=true is forbidden")
    security_opt = service.get("security_opt", [])
    if isinstance(security_opt, list) and any("unconfined" in str(item).lower() for item in security_opt):
        errors.append(f"{service_name}: unconfined security profile is forbidden")

    caps = service.get("cap_add", [])
    if isinstance(caps, list):
        normalized = {_capability_name(item) for item in caps}
        forbidden = sorted(normalized & FORBIDDEN_CAPS)
        if forbidden:
            errors.append(f"{service_name}: forbidden capabilities: {', '.join(forbidden)}")

    environment = _env_map(service)
    for key, value in environment.items():
        if PEM_MARKER.search(str(value)):
            errors.append(f"{service_name}: {key} contains inline PEM material")
        if FILE_ENV.fullmatch(key):
            if not str(value).startswith("/run/secrets/"):
                errors.append(f"{service_name}: {key} must point below /run/secrets/")
        elif SENSITIVE_ENV.search(key):
            errors.append(f"{service_name}: {key} must use a *_FILE secret reference")

    networks = _network_names(service)
    if not networks:
        errors.append(f"{service_name}: an explicit non-host network is required")


def _check_ports(service_name: str, service: dict[str, Any], errors: list[str], loopback_only: bool) -> None:
    for port in _published_ports(service):
        host_ip = str(port.get("host_ip", "")).strip().lower()
        if loopback_only and host_ip not in {"127.0.0.1", "::1", "localhost"}:
            errors.append(f"{service_name}: published ports must bind loopback only")


def _check_secret_references(config: dict[str, Any], errors: list[str]) -> None:
    declared = _as_mapping(config.get("secrets"))
    if not declared:
        errors.append("top-level secrets are required")
        return
    for name, definition in declared.items():
        if not isinstance(definition, dict) or not definition.get("file"):
            errors.append(f"secret {name}: an owner-managed file source is required")
        elif str(definition["file"]).strip() == "":
            errors.append(f"secret {name}: an owner-managed file source is required")
    for service_name, service in _as_mapping(config.get("services")).items():
        for name in _secret_names(_as_mapping(service)):
            if name not in declared:
                errors.append(f"{service_name}: secret {name} is not declared")


def validate_config(config: dict[str, Any]) -> list[str]:
    """Return deterministic, human-readable violations for normalized Compose JSON."""
    errors: list[str] = []
    if not isinstance(config, dict):
        return ["Compose config must be a JSON object"]
    services = _as_mapping(config.get("services"))
    networks = _as_mapping(config.get("networks"))
    if not services:
        errors.append("at least one service is required")
    if not networks:
        errors.append("top-level networks are required")
    if any(str(name).lower() == "default" for name in networks) and len(networks) == 1:
        errors.append("an explicit named network is required; implicit default-only networking is not allowed")

    worker_names = sorted(name for name in services if name == "sec-worker" or name.startswith("sec-worker-"))
    required = {"sec-server", "sec-updater", "postgres"}
    for name in sorted(required - set(services)):
        errors.append(f"required service {name} is missing")
    if not worker_names:
        errors.append("at least one sec-worker service is required")

    _check_secret_references(config, errors)

    for service_name, raw_service in services.items():
        service = _as_mapping(raw_service)
        _check_common(service_name, service, errors)

        if service_name == "sec-server":
            if len(_network_names(service)) < 2:
                errors.append("sec-server: control and worker networks are both required")
            _check_ports(service_name, service, errors, loopback_only=True)
            env = _env_map(service)
            targets = _secret_targets(service)
            for key in ("TLS_CERT_FILE", "TLS_KEY_FILE"):
                value = str(env.get(key, ""))
                if not value:
                    errors.append(f"sec-server: {key} is required")
                elif value not in targets:
                    errors.append(f"sec-server: {key} must reference a mounted service secret")
        elif service_name == "postgres":
            if _published_ports(service):
                errors.append("postgres: host port publishing is forbidden")
            environment = _env_map(service)
            if "POSTGRES_PASSWORD_FILE" not in environment:
                errors.append("postgres: POSTGRES_PASSWORD_FILE is required")
            if not _secret_names(service):
                errors.append("postgres: database password secret is required")
        elif service_name == "sec-updater":
            if _published_ports(service):
                errors.append("sec-updater: host port publishing is forbidden")
            user = str(service.get("user", "")).strip().lower()
            if user in {"", "0", "root", "0:0", "root:root"}:
                errors.append("sec-updater: must run as a non-root user")
            rules = _volume_for_target(service, "/vuln-data")
            if rules is None or not _is_writable(rules):
                errors.append("sec-updater: /vuln-data must be an explicitly writable volume")
            env = _env_map(service)
            if not env.get("NODE_TOKEN_FILE"):
                errors.append("sec-updater: NODE_TOKEN_FILE is required")
        elif service_name in worker_names:
            if _published_ports(service):
                errors.append(f"{service_name}: host port publishing is forbidden")
            caps = service.get("cap_add", [])
            actual_caps = {_capability_name(item) for item in caps} if isinstance(caps, list) else set()
            if actual_caps - WORKER_CAPS:
                errors.append(f"{service_name}: cap_add is limited to NET_ADMIN, SETUID and SETGID")
            if not WORKER_CAPS.issubset(actual_caps):
                errors.append(f"{service_name}: supervisor capabilities NET_ADMIN, SETUID and SETGID are required")
            rules = _volume_for_target(service, "/vuln-data")
            if rules is None or not _is_read_only(rules):
                errors.append(f"{service_name}: /vuln-data must be read-only")
            runtime = _volume_for_target(service, "/runtime")
            if runtime is None or not _is_writable(runtime):
                errors.append(f"{service_name}: /runtime must be an explicitly writable private volume")
            if not _env_map(service).get("NODE_TOKEN_FILE"):
                errors.append(f"{service_name}: NODE_TOKEN_FILE is required")

        if service_name not in worker_names and isinstance(service.get("cap_add"), list) and service.get("cap_add"):
            errors.append(f"{service_name}: cap_add is reserved for the Worker supervisor")

    return sorted(set(errors))


def _compose_json(path: Path) -> dict[str, Any]:
    command = ["docker", "compose", "-f", str(path), "config", "--format", "json"]
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
    except OSError as error:
        raise RuntimeError(f"unable to run Docker Compose: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown Compose error"
        raise RuntimeError(f"Docker Compose normalization failed: {detail}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"Docker Compose returned invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise RuntimeError("Docker Compose JSON must be an object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("compose_file", type=Path, help="Compose YAML file to normalize and validate")
    args = parser.parse_args(argv)
    try:
        config = _compose_json(args.compose_file)
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    errors = validate_config(config)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"deployment security validation failed ({len(errors)} violation(s))", file=sys.stderr)
        return 1
    print("deployment security validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
