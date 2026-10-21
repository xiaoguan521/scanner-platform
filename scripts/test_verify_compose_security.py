#!/usr/bin/env python3
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_compose_security as validator


def valid_config():
    return {
        "networks": {"control_net": {}, "worker_net": {}},
        "secrets": {
            "db_password": {"file": "/run/fixture/db_password"},
            "server_cert": {"file": "/run/fixture/server.crt"},
            "server_key": {"file": "/run/fixture/server.key"},
            "worker_token": {"file": "/run/fixture/worker.token"},
            "updater_token": {"file": "/run/fixture/updater.token"},
        },
        "services": {
            "postgres": {
                "environment": {"POSTGRES_PASSWORD_FILE": "/run/secrets/db_password"},
                "networks": {"control_net": None},
                "secrets": [{"source": "db_password", "target": "/run/secrets/db_password"}],
            },
            "sec-server": {
                "environment": {
                    "TLS_CERT_FILE": "/run/secrets/server.crt",
                    "TLS_KEY_FILE": "/run/secrets/server.key",
                    "NODE_TOKEN_FILE": "/run/secrets/worker_token",
                },
                "networks": {"control_net": None, "worker_net": None},
                "ports": [{"host_ip": "127.0.0.1", "target": 8080, "published": "8080"}],
                "secrets": [
                    {"source": "server_cert", "target": "/run/secrets/server.crt"},
                    {"source": "server_key", "target": "/run/secrets/server.key"},
                    {"source": "worker_token", "target": "/run/secrets/worker_token"},
                ],
            },
            "sec-updater": {
                "environment": {"NODE_TOKEN_FILE": "/run/secrets/updater_token"},
                "networks": {"worker_net": None},
                "secrets": [{"source": "updater_token", "target": "/run/secrets/updater.token"}],
                "user": "10001:10001",
                "volumes": [{"target": "/vuln-data", "read_only": False}],
            },
            "sec-worker-1": {
                "cap_add": ["NET_ADMIN", "SETUID", "SETGID"],
                "environment": {"NODE_TOKEN_FILE": "/run/secrets/worker_token"},
                "networks": {"worker_net": None},
                "secrets": [{"source": "worker_token", "target": "/run/secrets/worker.token"}],
                "volumes": [
                    {"target": "/vuln-data", "read_only": True},
                    {"target": "/runtime", "read_only": False},
                ],
            },
        },
    }


class ComposeSecurityTest(unittest.TestCase):
    def assertViolation(self, config, fragment):
        errors = validator.validate_config(config)
        self.assertTrue(any(fragment in error for error in errors), errors)

    def test_valid_fenced_deployment_passes(self):
        self.assertEqual(validator.validate_config(valid_config()), [])

    def test_host_network_and_privileged_worker_fail(self):
        config = valid_config()
        config["services"]["sec-worker-1"]["network_mode"] = "host"
        config["services"]["sec-worker-1"]["privileged"] = True
        self.assertViolation(config, "network_mode is forbidden")
        self.assertViolation(config, "privileged=true")

    def test_shared_network_namespace_and_non_worker_capability_fail(self):
        config = valid_config()
        config["services"]["sec-worker-1"]["network_mode"] = "service:sec-server"
        config["services"]["sec-server"]["cap_add"] = ["NET_ADMIN"]
        config["services"]["sec-server"]["environment"].pop("TLS_KEY_FILE")
        self.assertViolation(config, "network_mode is forbidden")
        self.assertViolation(config, "cap_add is reserved for the Worker supervisor")
        self.assertViolation(config, "TLS_KEY_FILE is required")

    def test_worker_rules_must_be_read_only_and_runtime_writable(self):
        config = valid_config()
        config["services"]["sec-worker-1"]["volumes"][0]["read_only"] = False
        config["services"]["sec-worker-1"]["volumes"][1]["read_only"] = True
        self.assertViolation(config, "/vuln-data must be read-only")
        self.assertViolation(config, "/runtime must be an explicitly writable")

    def test_sensitive_environment_and_inline_key_fail(self):
        config = valid_config()
        config["services"]["sec-server"]["environment"] = {
            "NODE_TOKEN": "token-from-env",
            "TLS_KEY": "private-key-from-env",
        }
        self.assertViolation(config, "NODE_TOKEN must use a *_FILE")
        self.assertViolation(config, "TLS_KEY must use a *_FILE")

        config["services"]["sec-server"]["environment"]["TLS_CERT_FILE"] = "inline-cert"
        self.assertViolation(config, "TLS_CERT_FILE must point below /run/secrets/")
        config["services"]["sec-server"]["environment"]["PUBLIC_CERT"] = "-----BEGIN PUBLIC KEY-----fixture"
        self.assertViolation(config, "contains inline PEM")

    def test_worker_capability_and_port_limits_fail(self):
        config = valid_config()
        worker = config["services"]["sec-worker-1"]
        worker["cap_add"] = ["NET_ADMIN", "SYS_ADMIN"]
        worker["ports"] = [{"host_ip": "127.0.0.1", "target": 8080, "published": "8081"}]
        self.assertViolation(config, "forbidden capabilities")
        self.assertViolation(config, "host port publishing is forbidden")

    def test_updater_must_be_non_root_and_writable_rules(self):
        config = valid_config()
        updater = config["services"]["sec-updater"]
        updater["user"] = "root"
        updater["volumes"][0]["read_only"] = True
        self.assertViolation(config, "must run as a non-root user")
        self.assertViolation(config, "/vuln-data must be an explicitly writable")

    def test_server_ports_are_loopback_only(self):
        config = valid_config()
        config["services"]["sec-server"]["ports"][0]["host_ip"] = "0.0.0.0"
        self.assertViolation(config, "published ports must bind loopback only")

    def test_missing_declared_secret_and_network_are_rejected(self):
        config = valid_config()
        del config["secrets"]["worker_token"]
        config["services"]["sec-worker-1"]["networks"] = {}
        self.assertViolation(config, "secret worker_token is not declared")
        self.assertViolation(config, "an explicit non-host network is required")

    def test_fixture_is_not_mutated_by_validation(self):
        config = valid_config()
        original = copy.deepcopy(config)
        validator.validate_config(config)
        self.assertEqual(config, original)


if __name__ == "__main__":
    unittest.main()
