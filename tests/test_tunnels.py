#!/usr/bin/env python3
"""WireGuard tunnel (3.20): settings, nft rules, agent management, API.

The tests touch neither the system firewall nor the host WireGuard
interface: the nft and wg/ip calls are replaced by captured or dry-run
execution.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import gateway  # noqa: E402
import fail2ban as fail2ban_mod  # noqa: E402
import server  # noqa: E402
import settings_store  # noqa: E402
import tunnel as tunnel_mod  # noqa: E402

T = "inet hatarvedelem"


def key(byte: bytes) -> str:
    return base64.b64encode(byte * 32).decode("ascii")


KEY_A = key(b"a")
KEY_B = key(b"b")
KEY_C = key(b"c")
TOKEN = "t" * 32


def service(service_id: str = "mc", target_host: str = "mc",
            mappings=None, **over) -> dict:
    entry = {
        "id": service_id, "label": "Minecraft", "target_host": target_host,
        "enabled": True,
        "mappings": mappings if mappings is not None else [
            {"proto": "tcp", "listen": "25565", "target": "25565"},
        ],
    }
    entry.update(over)
    return entry


def mapping(proto: str = "tcp", listen="25565", target="25565") -> dict:
    return {"proto": proto, "listen": listen, "target": target}


def agent(agent_id: str = "home", address: str = "10.77.0.2", **over) -> dict:
    entry = {
        "id": agent_id, "label": "Otthon", "address": address,
        "private_key": KEY_A, "public_key": KEY_B,
        "preshared_key": KEY_C, "token": TOKEN, "enabled": True,
        "services": [],
    }
    entry.update(over)
    return entry


def tunnels(agents=None, **over) -> dict:
    data = {
        "port": 51820, "endpoint": "",
        "server_private_key": KEY_A, "server_public_key": KEY_B,
        "agents": list(agents or []),
    }
    data.update(over)
    return data


def proxy_entry(**over) -> dict:
    entry = {
        "id": "mc", "label": "Minecraft", "proto": "tcp", "type": "forward",
        "listen_port": 25565, "target_ip": "192.168.10.20",
        "target_port": 25565, "ifaces": "wan", "snat": False, "enabled": True,
    }
    entry.update(over)
    return entry


def domain_service(service_id: str = "web",
                   domain: str = "web.example.com",
                   target_host: str = "web", mappings=None,
                   **over) -> dict:
    """Domain-mode (behind Caddy) service: one TCP, with an empty listen port."""
    entry = service(
        service_id=service_id, target_host=target_host,
        mappings=mappings if mappings is not None else [
            mapping("tcp", "", "8080"),
        ],
        domain=domain, **over,
    )
    return entry


def domain_state(services, domains=("example.com",), routes=(),
                 portal_domain: str = "") -> dict:
    """validate_state input with a proxy root and tunnel services."""
    return {
        "proxy_domains": list(domains),
        "proxy_routes": list(routes),
        "portal_domain": portal_domain,
        "tunnels": tunnels(agents=[agent(services=list(services))]),
    }


class TunnelSettingsTests(unittest.TestCase):
    """Validation of the tunnels section with the existing settings rules."""

    def test_defaults_and_normalization(self) -> None:
        self.assertEqual(
            settings_store.validate_state({})["tunnels"],
            settings_store.default_tunnels(),
        )
        result = settings_store.validate_state({
            "tunnels": tunnels(agents=[agent(services=[
                service(mappings=[
                    mapping("tcp", "8000-8002", "18000-18002"),
                ]),
                service(
                    service_id="web", target_host="web",
                    mappings=[mapping("udp", "8080", "8080")],
                ),
            ])]),
        })
        services = result["tunnels"]["agents"][0]["services"]
        self.assertEqual(services[0]["target_host"], "mc")
        self.assertEqual(services[0]["mappings"], [
            {"proto": "tcp", "listen": "8000-8002", "target": "18000-18002"},
        ])
        self.assertEqual(services[1]["target_host"], "web")
        self.assertNotIn("tunnel_port", services[1])
        self.assertEqual(result["tunnels"]["port"], 51820)

    def test_limits(self) -> None:
        too_many_agents = [
            agent(agent_id=f"a{i}", address=f"10.77.0.{i + 2}")
            for i in range(settings_store.MAX_TUNNEL_AGENTS + 1)
        ]
        with self.assertRaises(settings_store.SettingsError):
            settings_store.validate_state(
                {"tunnels": tunnels(agents=too_many_agents)}
            )
        too_many_services = [
            service(
                service_id=f"s{i}",
                mappings=[mapping("tcp", str(20000 + i), "9000")],
            )
            for i in range(settings_store.MAX_TUNNEL_SERVICES + 1)
        ]
        with self.assertRaises(settings_store.SettingsError):
            settings_store.validate_state({"tunnels": tunnels(
                agents=[agent(services=too_many_services)]
            )})

    def test_listen_ports_shared_with_port_proxies(self) -> None:
        # The same protocol and port collides with the port proxy.
        with self.assertRaises(settings_store.SettingsError):
            settings_store.validate_state({
                "port_proxies": [proxy_entry()],
                "tunnels": tunnels(agents=[agent(services=[service(
                    mappings=[mapping("tcp", "25565", "25565")]
                )])]),
            })
        # "both" reserves both protocols.
        with self.assertRaises(settings_store.SettingsError):
            settings_store.validate_state({
                "port_proxies": [proxy_entry(proto="udp")],
                "tunnels": tunnels(agents=[agent(services=[service(
                    mappings=[mapping("both", "25565", "25565")]
                )])]),
            })
        # Two agents cannot get the same listen port.
        with self.assertRaises(settings_store.SettingsError):
            settings_store.validate_state({"tunnels": tunnels(agents=[
                agent(services=[service()]),
                agent(
                    agent_id="home2", address="10.77.0.3",
                    services=[service(service_id="mc2")],
                ),
            ])})
        # The same port is allowed on a different protocol.
        result = settings_store.validate_state({
            "port_proxies": [proxy_entry(proto="udp")],
            "tunnels": tunnels(agents=[agent(services=[service()])]),
        })
        self.assertEqual(len(result["tunnels"]["agents"][0]["services"]), 1)

    def test_global_uniqueness_with_ranges(self) -> None:
        first = agent(services=[service(mappings=[
            mapping("tcp", "8000-8099", "18000-18099"),
        ])])
        # The same protocol collides within the range.
        with self.assertRaises(settings_store.SettingsError):
            settings_store.validate_state({"tunnels": tunnels(agents=[
                first,
                agent(
                    agent_id="home2", address="10.77.0.3",
                    services=[service(
                        service_id="web",
                        mappings=[mapping("tcp", "8050", "19050")],
                    )],
                ),
            ])})
        # UDP on the same port does not collide with the TCP range.
        result = settings_store.validate_state({"tunnels": tunnels(agents=[
            first,
            agent(
                agent_id="home2", address="10.77.0.3",
                services=[service(
                    service_id="web",
                    mappings=[mapping("udp", "8050", "19050")],
                )],
            ),
        ])})
        self.assertEqual(len(result["tunnels"]["agents"]), 2)
        # "both" reserves both protocols of the range.
        with self.assertRaises(settings_store.SettingsError):
            settings_store.validate_state({"tunnels": tunnels(agents=[
                first,
                agent(
                    agent_id="home2", address="10.77.0.3",
                    services=[service(
                        service_id="web",
                        mappings=[mapping("both", "8090-8091", "19000-19001")],
                    )],
                ),
            ])})

    def test_wireguard_port_is_not_a_listen_port(self) -> None:
        wg = settings_store.TUNNEL_DEFAULT_PORT
        with self.assertRaises(settings_store.SettingsError):
            settings_store.validate_state({"tunnels": tunnels(agents=[
                agent(services=[service(
                    mappings=[mapping("udp", str(wg), "9000")]
                )])
            ])})
        with self.assertRaises(settings_store.SettingsError):
            settings_store.validate_state({
                "port_proxies": [proxy_entry(proto="udp", listen_port=wg)],
                "tunnels": tunnels(agents=[agent()]),
            })
        # TCP on the same port does not collide; nor does a disabled agent.
        settings_store.validate_state({
            "port_proxies": [proxy_entry(proto="tcp", listen_port=wg)],
            "tunnels": tunnels(agents=[agent()]),
        })
        settings_store.validate_state({"tunnels": tunnels(agents=[
            agent(enabled=False, services=[service(
                mappings=[mapping("udp", str(wg), "9000")]
            )])
        ])})

    def test_reserved_ports(self) -> None:
        for port in (22, 53, 67, 80, 443, 2019,
                     settings_store.PORTAL_PORT):
            with self.assertRaises(settings_store.SettingsError):
                settings_store.validate_state({"tunnels": tunnels(agents=[
                    agent(services=[service(
                        mappings=[mapping("tcp", str(port), "9000")]
                    )])
                ])})
        # A reserved port inside the range is also an error.
        for listen, target in (
            ("8090-8110", "19090-19110"),
            ("8000-8010", "20-30"),
        ):
            with self.assertRaises(settings_store.SettingsError):
                settings_store.validate_state({"tunnels": tunnels(agents=[
                    agent(services=[service(
                        mappings=[mapping("tcp", listen, target)]
                    )])
                ])})
        for port in (22, 2019, 0, 65536):
            with self.assertRaises(settings_store.SettingsError):
                settings_store.validate_state({"tunnels": tunnels(agents=[
                    agent(services=[service(
                        mappings=[mapping("tcp", "9000", str(port))]
                    )])
                ])})
        for port in (1023, 65536, 80, settings_store.PORTAL_PORT):
            with self.assertRaises(settings_store.SettingsError):
                settings_store.validate_state({"tunnels": tunnels(port=port)})
        # Two services cannot get the same listen port.
        with self.assertRaises(settings_store.SettingsError):
            settings_store.validate_state({"tunnels": tunnels(agents=[
                agent(services=[
                    service(service_id="a"),
                    service(service_id="b"),
                ])
            ])})

    def test_mapping_pairing_and_conflicts(self) -> None:
        # Range-to-range pairing by index.
        ports = settings_store.tunnel_service_ports(service(mappings=[
            mapping("tcp", "8000-8002", "18000-18002"),
        ]))
        self.assertEqual(
            [(p["listen_port"], p["target_port"]) for p in ports],
            [(8000, 18000), (8001, 18001), (8002, 18002)],
        )
        self.assertTrue(all(p["tunnel_port"] == p["listen_port"]
                            for p in ports))
        # A different length is rejected; one target port cannot serve several listeners.
        for listen, target in (("8000-8002", "18000-18003"),
                               ("8000-8002", "18000")):
            with self.assertRaises(settings_store.SettingsError):
                settings_store.validate_state({"tunnels": tunnels(agents=[
                    agent(services=[service(
                        mappings=[mapping("tcp", listen, target)]
                    )])
                ])})
        # More than 256 ports cannot be mapped.
        with self.assertRaises(settings_store.SettingsError):
            settings_store.validate_state({"tunnels": tunnels(agents=[
                agent(services=[service(
                    mappings=[mapping("tcp", "1-300", "2000-2299")]
                )])
            ])})
        # Effective per-agent port limit.
        with self.assertRaises(settings_store.SettingsError):
            settings_store.validate_state({"tunnels": tunnels(agents=[
                agent(services=[
                    service(
                        service_id=f"s{i}",
                        mappings=[mapping(
                            "tcp", f"{20000 + i * 256}-"
                            f"{20255 + i * 256}",
                            f"{30000 + i * 256}-{30255 + i * 256}",
                        )],
                    )
                    for i in range(2)
                ])
            ])})
        # A repeated protocol on the same port is an error.
        with self.assertRaises(settings_store.SettingsError):
            settings_store.validate_state({"tunnels": tunnels(agents=[
                agent(services=[service(mappings=[
                    mapping("tcp", "8000", "9000"),
                    mapping("tcp", "8000", "9000"),
                ])])
            ])})
        # tcp + udp to the same target port merge into "both".
        merged = settings_store.agent_services_expanded(agent(services=[service(
            mappings=[
                mapping("tcp", "8000", "9000"),
                mapping("udp", "8000", "9000"),
            ]
        )]))
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["proto"], "both")
        self.assertEqual(merged[0]["tunnel_port"], 8000)
        # A different target port on the same listen port is an error.
        with self.assertRaises(settings_store.SettingsError):
            settings_store.validate_state({"tunnels": tunnels(agents=[
                agent(services=[service(mappings=[
                    mapping("tcp", "8000", "9000"),
                    mapping("udp", "8000", "9001"),
                ])])
            ])})
        # The tcp/udp pair of two services also merges.
        merged = settings_store.agent_services_expanded(agent(services=[
            service(service_id="a", mappings=[mapping("tcp", "8000", "9000")]),
            service(service_id="b", mappings=[mapping("udp", "8000", "9000")]),
        ]))
        self.assertEqual([(m["proto"], m["listen_port"]) for m in merged],
                         [("both", 8000)])

    def test_ordered_port_pairing_and_canonical_round_trip(self) -> None:
        # The lists pair in the order entered: 8000 -> 9001, not 9000.
        result = settings_store.validate_state({"tunnels": tunnels(agents=[
            agent(services=[service(mappings=[
                mapping("tcp", "8000,8001", "9001,9000"),
            ])])
        ])})
        stored = result["tunnels"]["agents"][0]["services"][0]["mappings"]
        self.assertEqual(stored, [{
            "proto": "tcp", "listen": "8000-8001",
            "target": "9001, 9000",
        }])
        ports = settings_store.tunnel_service_ports(
            result["tunnels"]["agents"][0]["services"][0]
        )
        self.assertEqual(
            [(p["listen_port"], p["target_port"]) for p in ports],
            [(8000, 9001), (8001, 9000)],
        )
        # Canonical storage sorts pairwise and writes both sides in the same
        # order; reading it back is stable.
        again = settings_store.validate_state(result)
        self.assertEqual(
            again["tunnels"]["agents"][0]["services"][0]["mappings"], stored
        )
        # Mixed list and range: the range expands upward, but the
        # order of list items matters for pairing.
        mixed = settings_store.validate_state({"tunnels": tunnels(agents=[
            agent(services=[service(mappings=[
                mapping("tcp", "8002-8003,8000", "9001,9000,9002"),
            ])])
        ])})
        mixed_stored = mixed["tunnels"]["agents"][0]["services"][0]["mappings"]
        self.assertEqual(mixed_stored, [{
            "proto": "tcp", "listen": "8000, 8002-8003",
            "target": "9002, 9001, 9000",
        }])
        mixed_ports = settings_store.tunnel_service_ports(
            mixed["tunnels"]["agents"][0]["services"][0]
        )
        self.assertEqual(
            [(p["listen_port"], p["target_port"]) for p in mixed_ports],
            [(8000, 9002), (8002, 9001), (8003, 9000)],
        )
        # A repeated target port is allowed: several listen ports to the same place.
        duplicate_target = settings_store.validate_state({"tunnels": tunnels(
            agents=[agent(services=[service(mappings=[
                mapping("tcp", "8000,8001", "9000,9000"),
            ])])]
        )})
        self.assertEqual(
            settings_store.tunnel_service_ports(
                duplicate_target["tunnels"]["agents"][0]["services"][0]
            ),
            [
                {"proto": "tcp", "listen_port": 8000, "target_port": 9000,
                 "tunnel_port": 8000},
                {"proto": "tcp", "listen_port": 8001, "target_port": 9000,
                 "tunnel_port": 8001},
            ],
        )
        # A repeated listen port is an error: same pair or different target alike.
        for target in ("9000,9000", "9000,9001"):
            with self.assertRaises(settings_store.SettingsError):
                settings_store.validate_state({"tunnels": tunnels(agents=[
                    agent(services=[service(mappings=[
                        mapping("tcp", "8000,8000", target),
                    ])])
                ])})

    def test_old_shape_is_migrated(self) -> None:
        result = settings_store.validate_state({"tunnels": tunnels(agents=[
            agent(services=[{
                "id": "mc", "label": "Minecraft", "proto": "both",
                "listen_port": 25565, "tunnel_port": 41000,
                "target": "mc:25565", "enabled": True,
            }]),
        ])})
        service_row = result["tunnels"]["agents"][0]["services"][0]
        self.assertEqual(service_row, {
            "id": "mc", "label": "Minecraft", "target_host": "mc",
            "enabled": True, "public": False, "domain": "",
            "mappings": [
                {"proto": "both", "listen": "25565", "target": "25565"},
            ],
        })
        # The old, malformed shape remains fail-closed.
        with self.assertRaises(settings_store.SettingsError):
            settings_store.validate_state({"tunnels": tunnels(agents=[
                agent(services=[{
                    "id": "mc", "label": "Minecraft", "proto": "tcp",
                    "listen_port": 25565, "tunnel_port": 41000,
                    "target": "mc", "enabled": True,
                }]),
            ])})

    def test_keys_tokens_and_addresses(self) -> None:
        for bad_key in ("nem-kulcs", base64.b64encode(b"x" * 31).decode()):
            with self.assertRaises(settings_store.SettingsError):
                settings_store.validate_state({"tunnels": tunnels(
                    agents=[agent(private_key=bad_key)]
                )})
        with self.assertRaises(settings_store.SettingsError):
            settings_store.validate_state({"tunnels": {
                **settings_store.default_tunnels(),
                "server_private_key": "", "server_public_key": "",
                "agents": [agent()],
            }})
        for token in ("short", "a" * 31, "a" * 32 + "!"):
            with self.assertRaises(settings_store.SettingsError):
                settings_store.validate_state({"tunnels": tunnels(
                    agents=[agent(token=token)]
                )})
        for address in ("10.77.0.1", "10.77.0.255", "10.77.1.2",
                        "192.168.1.5", "nem-cim"):
            with self.assertRaises(settings_store.SettingsError):
                settings_store.validate_state({"tunnels": tunnels(
                    agents=[agent(address=address)]
                )})
        with self.assertRaises(settings_store.SettingsError):
            settings_store.validate_state({"tunnels": tunnels(agents=[
                agent(), agent(agent_id="other"),
            ])})
        with self.assertRaises(settings_store.SettingsError):
            settings_store.validate_state({"tunnels": tunnels(agents=[
                agent(services=[service(), service()]),
            ])})

    def test_service_target_and_protocol(self) -> None:
        for target_host in ("", "bad host", "mc:80", None):
            with self.assertRaises(settings_store.SettingsError):
                settings_store.validate_state({"tunnels": tunnels(agents=[
                    agent(services=[service(target_host=target_host)])
                ])})
        for proto in ("sctp", "", None):
            with self.assertRaises(settings_store.SettingsError):
                settings_store.validate_state({"tunnels": tunnels(agents=[
                    agent(services=[service(
                        mappings=[mapping(proto, "8000", "9000")]
                    )])
                ])})
        # An empty or missing mapping list is an error.
        missing = service()
        del missing["mappings"]
        for broken in (missing, service(mappings=[])):
            with self.assertRaises(settings_store.SettingsError):
                settings_store.validate_state({"tunnels": tunnels(agents=[
                    agent(services=[broken])
                ])})
        # Comma, space, semicolon and dash are all accepted.
        ports = settings_store.tunnel_service_ports(service(mappings=[
            mapping("tcp", "8000, 8001;8002–8004", "18000 18001;18002—18004"),
        ]))
        self.assertEqual([p["listen_port"] for p in ports],
                         [8000, 8001, 8002, 8003, 8004])
        self.assertEqual([p["target_port"] for p in ports],
                         [18000, 18001, 18002, 18003, 18004])
        with self.assertRaises(settings_store.SettingsError):
            settings_store.validate_state({"tunnels": tunnels(
                endpoint="bad host"
            )})


    def test_public_flag_default_and_validation(self) -> None:
        plain = settings_store.validate_state({"tunnels": tunnels(agents=[
            agent(services=[service()])
        ])})["tunnels"]["agents"][0]["services"][0]
        self.assertIs(plain["public"], False)
        self.assertEqual(plain["domain"], "")
        public = settings_store.validate_state({"tunnels": tunnels(agents=[
            agent(services=[service(public=True)])
        ])})["tunnels"]["agents"][0]["services"][0]
        self.assertIs(public["public"], True)
        for bad in ("true", 1, None, []):
            with self.subTest(public=bad):
                with self.assertRaises(settings_store.SettingsError):
                    settings_store.validate_state({"tunnels": tunnels(
                        agents=[agent(services=[service(public=bad)])]
                    )})

    def test_domain_normalization_and_auto_internal_port(self) -> None:
        result = settings_store.validate_state(domain_state([
            domain_service(domain="Web.Example.COM"),
        ]))
        row = result["tunnels"]["agents"][0]["services"][0]
        self.assertEqual(row["domain"], "web.example.com")
        self.assertEqual(len(row["mappings"]), 1)
        self.assertEqual(row["mappings"][0]["proto"], "tcp")
        self.assertEqual(row["mappings"][0]["target"], "8080")
        internal = int(row["mappings"][0]["listen"])
        self.assertGreaterEqual(
            internal, settings_store.TUNNEL_DOMAIN_PORT_LOW
        )
        self.assertLessEqual(internal, settings_store.TUNNEL_DOMAIN_PORT_HIGH)
        # Revalidation keeps the explicit internal port.
        again = settings_store.validate_state(result)["tunnels"][
            "agents"][0]["services"][0]
        self.assertEqual(again["mappings"][0]["listen"], str(internal))

    def test_domain_service_challenge_validation_and_clearing(self) -> None:
        result = settings_store.validate_state(domain_state([
            domain_service(challenge={"triggers": ["always"],
                                      "interval_hours": 24}),
        ]))
        row = result["tunnels"]["agents"][0]["services"][0]
        self.assertEqual(row["challenge"]["triggers"], ["always"])
        # Empty trigger list: no challenge, the key is omitted.
        cleared = settings_store.validate_state(domain_state([
            domain_service(challenge={"triggers": []}),
        ]))["tunnels"]["agents"][0]["services"][0]
        self.assertNotIn("challenge", cleared)
        # A challenge cannot be given for a non-domain service.
        with self.assertRaises(settings_store.SettingsError):
            settings_store.validate_state({"tunnels": tunnels(agents=[
                agent(services=[service(
                    challenge={"triggers": ["always"]}
                )])
            ])})
        # An unknown trigger and a bad interval are errors alike.
        for challenge in (
            {"triggers": ["unknown"]},
            {"triggers": ["interval"], "interval_hours": 0},
            {"triggers": "always"},
        ):
            with self.subTest(challenge=challenge):
                with self.assertRaises(settings_store.SettingsError):
                    settings_store.validate_state(domain_state([
                        domain_service(challenge=challenge),
                    ]))

    def test_domain_must_be_strict_subdomain(self) -> None:
        bad = (
            "web",                       # no dot
            "*.example.com",             # wildcard
            "web.example.com:443",       # port
            "http://web.example.com",    # scheme
            "-web.example.com",          # leading hyphen
            "web..example.com",          # empty label
            "web.example.com.",          # trailing dot
            "example.com",               # the root itself
            "other.test",                # not under the root
        )
        for domain in bad:
            with self.subTest(domain=domain):
                with self.assertRaises(settings_store.SettingsError):
                    settings_store.validate_state(domain_state([
                        domain_service(domain=domain),
                    ]))

    def test_domain_conflicts_with_portal_routes_and_other_services(
        self,
    ) -> None:
        routes = [{"name": "nas", "root": "example.com", "port": 80}]
        # Neither the portal address nor a proxy entry host can be a service domain.
        for domain in ("portal.example.com", "nas.example.com"):
            with self.subTest(domain=domain):
                with self.assertRaises(settings_store.SettingsError):
                    settings_store.validate_state(domain_state(
                        [domain_service(domain=domain)],
                        routes=routes,
                        portal_domain="portal.example.com",
                    ))
        # The same domain on two services (case-insensitive) is an error.
        with self.assertRaises(settings_store.SettingsError):
            settings_store.validate_state(domain_state([
                domain_service(service_id="a", domain="web.example.com"),
                domain_service(service_id="b", domain="WEB.example.com"),
            ]))
        # It must fall under the longest matching root.
        result = settings_store.validate_state(domain_state(
            [domain_service(domain="web.sub.example.com")],
            domains=("example.com", "sub.example.com"),
        ))
        self.assertEqual(
            result["tunnels"]["agents"][0]["services"][0]["domain"],
            "web.sub.example.com",
        )

    def test_domain_requires_single_tcp_mapping_and_target(self) -> None:
        cases = {
            "two mappings": domain_service(mappings=[
                mapping("tcp", "", "8080"), mapping("tcp", "", "8081"),
            ]),
            "udp": domain_service(mappings=[mapping("udp", "", "8080")]),
            "both": domain_service(mappings=[mapping("both", "", "8080")]),
            "two target ports": domain_service(mappings=[
                mapping("tcp", "", "8080,8081"),
            ]),
            "two internal ports": domain_service(mappings=[
                mapping("tcp", "41000,41001", "8080"),
            ]),
            "without target host": domain_service(target_host=""),
            "target port 22": domain_service(mappings=[
                mapping("tcp", "", "22"),
            ]),
            "reserved internal port": domain_service(mappings=[
                mapping("tcp", str(settings_store.PORTAL_PORT), "8080"),
            ]),
        }
        for label, broken in cases.items():
            with self.subTest(label):
                with self.assertRaises(settings_store.SettingsError):
                    settings_store.validate_state(domain_state([broken]))

    def test_domain_internal_port_avoids_explicit_and_reserved(self) -> None:
        explicit = service(
            service_id="plain", target_host="mc",
            mappings=[mapping("tcp", str(
                settings_store.TUNNEL_DOMAIN_PORT_LOW
            ), "25565")],
        )
        result = settings_store.validate_state(domain_state([
            explicit,
            domain_service(service_id="a", domain="a.example.com"),
            domain_service(service_id="b", domain="b.example.com"),
        ]))
        services = result["tunnels"]["agents"][0]["services"]
        ports = [int(row["mappings"][0]["listen"]) for row in services[1:]]
        self.assertEqual(ports[0], settings_store.TUNNEL_DOMAIN_PORT_LOW + 1)
        self.assertEqual(ports[1], settings_store.TUNNEL_DOMAIN_PORT_LOW + 2)
        self.assertEqual(len(set(ports)), 2)
        # Reserved ports (WG, portal) cannot be handed out.
        self.assertNotIn(result["tunnels"]["port"], ports)
        self.assertNotIn(settings_store.PORTAL_PORT, ports)
        with mock.patch.object(
            settings_store, "TUNNEL_DOMAIN_PORT_HIGH",
            settings_store.TUNNEL_DOMAIN_PORT_LOW,
        ):
            with self.assertRaises(settings_store.SettingsError):
                settings_store.validate_state(domain_state([
                    service(
                        service_id="plain", target_host="mc",
                        mappings=[mapping("tcp", str(
                            settings_store.TUNNEL_DOMAIN_PORT_LOW
                        ), "25565")],
                    ),
                    domain_service(domain="x.example.com"),
                ]))

    def test_port_mode_multi_mapping_unaffected(self) -> None:
        result = settings_store.validate_state({"tunnels": tunnels(agents=[
            agent(services=[service(public=True, mappings=[
                mapping("tcp", "8000-8001", "9000-9001"),
                mapping("udp", "8200", "9200"),
            ])])
        ])})
        row = result["tunnels"]["agents"][0]["services"][0]
        self.assertEqual(len(row["mappings"]), 2)
        self.assertIs(row["public"], True)
        self.assertEqual(row["domain"], "")


class TunnelFirewallTests(unittest.TestCase):
    """nft: template ordering, WireGuard port and synthetic DNAT."""

    def setUp(self) -> None:
        self.fw = gateway.Firewall(
            dry_run=True, logger=lambda *_: None,
            lan_if="eth1", wan_if="eth0",
            lan_network=gateway._parse_lan_network("192.168.10.0/24"),
        )
        self.scripts: list[str] = []
        self.fw._run_script = self.scripts.append  # type: ignore[method-assign]

    def test_template_chain_and_jump_order(self) -> None:
        text = (ROOT / "deploy" / "dropjak.nft").read_text(
            encoding="utf-8"
        )
        self.assertIn(f"add chain {T} tunnel_input", text)
        self.assertIn(f"jump portproxy_input", text)
        self.assertIn(f"jump tunnel_input", text)
        self.assertLess(
            text.index(f"jump portproxy_input"),
            text.index(f"jump tunnel_input"),
        )
        self.assertIn(gateway.TUNNEL_CHAIN, gateway.RULESET_CHAINS)

    def test_wireguard_accept_only_with_enabled_agent(self) -> None:
        self.assertEqual(self.fw._tunnel_rules({}), [])
        self.assertEqual(
            self.fw._tunnel_rules(tunnels(agents=[agent(enabled=False)])), []
        )
        self.assertEqual(
            self.fw._tunnel_rules(
                tunnels(port=51999, agents=[agent()])
            ),
            [
                f'add rule {T} tunnel_input iifname "eth0" '
                "udp dport 51999 accept",
                f'add rule {T} tunnel_input iifname "dropjak0" '
                f"ip saddr 10.77.0.0/24 ip daddr 10.77.0.1 tcp dport "
                f"{settings_store.TUNNEL_SYNC_PORT} accept",
            ],
        )
        # Only the sync listener's port, never the portal port (DJ-15).
        self.assertNotEqual(
            settings_store.TUNNEL_SYNC_PORT, settings_store.PORTAL_PORT
        )
        self.fw.replace_custom(
            (), (), tunnels=tunnels(agents=[agent()])
        )
        script = self.scripts[-1]
        # Agents installed earlier still call the portal port: redirected
        # to the sync listener.
        self.assertIn(
            f'add rule {T} portproxy_nat iifname "dropjak0" '
            "ip saddr 10.77.0.0/24 ip daddr 10.77.0.1 tcp dport "
            f"{settings_store.PORTAL_PORT} redirect to "
            f":{settings_store.TUNNEL_SYNC_PORT}",
            script,
        )
        self.assertIn(f"add chain {T} tunnel_input", script)
        self.assertIn(f"flush chain {T} tunnel_input", script)
        self.assertIn(
            f'add rule {T} tunnel_input iifname "eth0" '
            "udp dport 51820 accept", script
        )

    def test_no_accept_without_agents(self) -> None:
        self.fw.replace_custom((), (), tunnels=settings_store.default_tunnels())
        script = self.scripts[-1]
        self.assertIn(f"flush chain {T} tunnel_input", script)
        self.assertNotIn("tunnel_input udp dport", script)
        self.assertNotIn("tunnel_input iifname", script)

    def test_synthetic_entries_render_dnat(self) -> None:
        state = tunnels(agents=[agent(services=[
            service(mappings=[mapping("tcp", "25565", "25565")]),
            service(service_id="voice", target_host="voice", mappings=[
                mapping("udp", "24454", "24454"),
            ]),
            service(service_id="both", target_host="web", mappings=[
                mapping("both", "8080", "80"),
            ]),
            service(service_id="off", enabled=False, target_host="web",
                    mappings=[mapping("tcp", "8081", "81")]),
        ])])
        entries = gateway.tunnel_proxy_entries(state)
        self.assertEqual(len(entries), 3)
        self.assertTrue(all(entry["_tunnel"] for entry in entries))
        by_listen = {entry["listen_port"]: entry for entry in entries}
        self.assertEqual(
            [entry["listen_port"] for entry in entries], [8080, 24454, 25565]
        )
        self.assertEqual(by_listen[25565]["target_ip"], "10.77.0.2")
        self.assertEqual(by_listen[25565]["target_port"], 25565)
        self.assertEqual(by_listen[25565]["id"], "tunnel:home:tcp:25565")
        rules = self.fw._portproxy_rules(entries)
        self.assertIn(
            f'add rule {T} portproxy_nat iifname "eth0" fib daddr type '
            "local tcp dport 25565 dnat ip to 10.77.0.2:25565",
            rules,
        )
        self.assertIn(
            f'add rule {T} portproxy_nat iifname "eth0" fib daddr type '
            "local udp dport 24454 dnat ip to 10.77.0.2:24454",
            rules,
        )
        self.assertTrue(any(
            "tcp dport 8080 dnat ip to 10.77.0.2:80" in rule
            for rule in rules
        ))
        self.assertTrue(any(
            "udp dport 8080 dnat ip to 10.77.0.2:80" in rule
            for rule in rules
        ))
        self.assertFalse(any("8081" in rule for rule in rules))
        self.assertFalse(any("portproxy_snat" in rule for rule in rules))
        self.assertFalse(any(
            "portproxy_input" in rule for rule in rules
        ))
        # A disabled agent yields no rule at all.
        self.assertEqual(gateway.tunnel_proxy_entries(
            tunnels(agents=[agent(enabled=False, services=[service()])])
        ), [])

    def test_tunnel_services_snat_only_not_preauth(self) -> None:
        state = tunnels(agents=[agent(services=[
            service(mappings=[mapping("both", "25565", "25565")]),
            service(service_id="off", enabled=False, target_host="web",
                    mappings=[mapping("tcp", "8081", "81")]),
        ])])
        self.fw.replace_custom((), (), tunnels=state)
        script = self.scripts[-1]
        # The forward grant is the template's ct original rule: the portal
        # grant is mandatory for the tunnel too, with no preauth bypass.
        self.assertIn(
            "ct original ip saddr . ct original proto-dst @allowed_tcp",
            (ROOT / "deploy" / "dropjak.nft").read_text(
                encoding="utf-8"
            ),
        )
        self.assertNotIn("preauth ct status dnat", script)
        for proto in ("tcp", "udp"):
            self.assertIn(
                f"add rule {T} portproxy_snat meta l4proto {proto} "
                "ct status dnat ct original proto-dst 25565 "
                "ip daddr 10.77.0.2 "
                f"{proto} dport 25565 masquerade",
                script,
            )
        self.assertNotIn("8081", script)

    def test_public_wan_services_get_preauth_accepts(self) -> None:
        state = tunnels(agents=[agent(services=[
            service(public=True, mappings=[mapping("both", "25565", "25565")]),
        ])])
        self.assertEqual(
            gateway.tunnel_public_preauth(state),
            [("tcp", 25565), ("udp", 25565)],
        )
        self.fw.replace_custom((), (), tunnels=state)
        script = self.scripts[-1]
        for proto in ("tcp", "udp"):
            self.assertIn(
                f'add rule {T} preauth iifname "eth0" ct status dnat '
                f"meta l4proto {proto} ct original proto-dst 25565 "
                f"meta mark set {self.fw.fwd_mark} accept",
                script,
            )
            self.assertIn(
                f"add rule {T} preauth ct state established "
                f"meta l4proto {proto} ct original proto-dst 25565 "
                f"meta mark set {self.fw.fwd_mark} accept",
                script,
            )
        # The LAN direction is deliberately not opened, and there is no
        # destination-less related rule (that would let all related traffic through).
        self.assertNotIn('preauth iifname "eth1" ct status dnat', script)
        self.assertNotIn("preauth ct state related", script)

    def test_public_preauth_absent_for_private_domain_and_disabled(
        self,
    ) -> None:
        state = tunnels(agents=[agent(services=[
            service(service_id="private", mappings=[
                mapping("tcp", "25565", "25565"),
            ]),
            domain_service(
                service_id="dom", domain="web.example.com",
                mappings=[mapping("tcp", "41000", "8080")],
                public=True,
            ),
            service(
                service_id="off", target_host="x", enabled=False,
                public=True, mappings=[mapping("tcp", "9000", "9000")],
            ),
        ])])
        self.assertEqual(gateway.tunnel_public_preauth(state), [])
        self.fw.replace_custom((), (), tunnels=state)
        script = self.scripts[-1]
        self.assertNotIn("preauth iifname", script)
        self.assertNotIn("41000", script)
        self.assertNotIn("9000", script)
        self.assertEqual(gateway.tunnel_public_preauth(tunnels(agents=[
            agent(enabled=False, services=[service(public=True)]),
        ])), [])
        # Without a known WAN interface the rule cannot be applied.
        firewall = gateway.Firewall(
            dry_run=True, logger=lambda *_: None,
            lan_if="eth1", wan_if="",
            lan_network=gateway._parse_lan_network("192.168.10.0/24"),
        )
        with self.assertRaises(gateway.FirewallError):
            firewall._custom_rules(tunnel_public=(("tcp", 25565),))
        with self.assertRaises(gateway.FirewallError):
            self.fw._custom_rules(tunnel_public=(("sctp", 25565),))

    def test_domain_service_has_no_wan_dnat_or_index_ports(self) -> None:
        state = tunnels(agents=[agent(services=[
            domain_service(
                domain="web.example.com",
                mappings=[mapping("tcp", "41000", "8080")],
            ),
        ])])
        self.assertEqual(gateway.tunnel_proxy_entries(state), [])
        index = settings_store.tunnel_service_index(state)
        entry = index["home/web"]
        self.assertEqual(entry["domain"], "web.example.com")
        self.assertIs(entry["public"], False)
        self.assertEqual(entry["tcp"], ())
        self.assertEqual(entry["udp"], ())
        self.assertEqual(
            entry["signature"],
            (("domain", 0, "web.example.com", 0),
             ("tcp", 41000, "web", 8080)),
        )
        expanded = settings_store.agent_services_expanded(state["agents"][0])
        self.assertEqual(expanded[0]["domain"], "web.example.com")
        self.assertIs(expanded[0]["public"], False)

    def test_existing_proxy_rule_strings_unchanged(self) -> None:
        alone = self.fw._portproxy_rules([proxy_entry()])
        self.assertEqual(alone, [
            f'add rule {T} portproxy_nat iifname "eth0" fib daddr type local '
            "tcp dport 25565 dnat ip to 192.168.10.20:25565",
        ])
        self.fw.replace_custom((), (), port_proxies=[proxy_entry()],
                               tunnels=settings_store.default_tunnels())
        script = self.scripts[-1]
        self.assertIn(alone[0], script)
        self.assertNotIn("tunnel_input udp dport", script)

    def test_synthetic_entries_invisible_to_changes_and_warnings(self) -> None:
        synthetic = gateway.tunnel_proxy_entries(tunnels(agents=[
            agent(services=[service()])
        ]))
        self.assertEqual(gateway.port_proxy_changes(synthetic, []), [])
        self.assertEqual(gateway.port_proxy_changes([], synthetic), [])
        self.assertEqual(
            gateway.port_proxy_warnings(
                synthetic, listening={(  "tcp", 25565)},
                published=set(), localnet=set(),
            ),
            [],
        )


class FakeRunner:
    """ip/wg stand-in: records the call and the stdin content."""

    def __init__(self, handler):
        self.handler = handler
        self.calls: list[tuple[list[str], str | None]] = []

    def __call__(self, args, input=None, capture_output=True, text=True,
                 timeout=None):
        args = list(args)
        self.calls.append((args, input))
        outcome = self.handler(args, input)
        if isinstance(outcome, Exception):
            raise outcome
        return subprocess.CompletedProcess(args, *outcome)


class TunnelManagerTests(unittest.TestCase):
    """The dropjak0 interface, peers, key files and status."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def manager(self, handler) -> tuple[tunnel_mod.TunnelManager, FakeRunner]:
        runner = FakeRunner(handler)
        return tunnel_mod.TunnelManager(
            run_dir=self.tmp.name, logger=lambda *_: None, runner=runner
        ), runner

    def test_reconcile_link_keys_peers_and_cleanup(self) -> None:
        seen: dict = {}
        public = key(b"p")
        psk = key(b"s")
        private = key(b"r")

        def handler(args, input):
            if args[0] == "ip":
                return 0, "", ""
            if args[:3] == ["wg", "show", "dropjak0"]:
                return 0, "STALE\n", ""
            if args[0] == "wg":
                for flag in ("private-key", "preshared-key"):
                    if flag in args:
                        path = args[args.index(flag) + 1]
                        seen[flag] = (
                            Path(path).read_text(encoding="ascii"),
                            oct(os.stat(path).st_mode & 0o777),
                        )
                return 0, "", ""
            return 0, "", ""

        manager, runner = self.manager(handler)
        state = tunnels(agents=[agent(
            public_key=public, preshared_key=psk
        )])
        state["server_private_key"] = private
        self.assertTrue(manager.reconcile(state))
        self.assertEqual(manager.error, "")
        calls = [call[0] for call in runner.calls]
        self.assertEqual(calls[0], [
            "ip", "link", "add", "dropjak0", "type", "wireguard"
        ])
        # replace: the address can be set idempotently (restarted namespace).
        self.assertEqual(calls[1], [
            "ip", "addr", "replace", "10.77.0.1/24", "dev", "dropjak0"
        ])
        self.assertEqual(calls[2], [
            "ip", "link", "set", "dropjak0", "mtu", "1420", "up"
        ])
        self.assertEqual(calls[3][:4], [
            "wg", "set", "dropjak0", "private-key"
        ])
        self.assertEqual(calls[3][-2:], ["listen-port", "51820"])
        self.assertEqual(calls[4][:6], [
            "wg", "set", "dropjak0", "peer", public, "preshared-key"
        ])
        self.assertEqual(calls[4][-2:], ["allowed-ips", "10.77.0.2/32"])
        self.assertEqual(calls[-1], [
            "wg", "set", "dropjak0", "peer", "STALE", "remove"
        ])
        self.assertEqual(seen["private-key"], (private + "\n", "0o600"))
        self.assertEqual(seen["preshared-key"], (psk + "\n", "0o600"))
        paths = [
            call[0][call[0].index(flag) + 1]
            for call in runner.calls
            for flag in ("private-key", "preshared-key")
            if flag in call[0]
        ]
        self.assertTrue(paths)
        for path in paths:
            self.assertFalse(Path(path).exists())

    def test_signature_skips_unrelated_saves(self) -> None:
        manager, runner = self.manager(lambda args, input: (0, "", ""))
        state = tunnels(agents=[agent()])
        self.assertTrue(manager.reconcile(state))
        count = len(runner.calls)
        self.assertFalse(manager.reconcile(json.loads(json.dumps(state))))
        self.assertEqual(len(runner.calls), count)
        state["port"] = 51999
        self.assertTrue(manager.reconcile(state))

    def test_disabled_agent_peer_is_removed(self) -> None:
        public = key(b"p")

        def handler(args, input):
            if args[:4] == ["wg", "show", "dropjak0", "peers"]:
                return 0, public + "\n", ""
            return 0, "", ""

        manager, runner = self.manager(handler)
        state = tunnels(agents=[agent(
            public_key=public, enabled=False
        )])
        self.assertTrue(manager.reconcile(state))
        calls = [call[0] for call in runner.calls]
        self.assertIn(
            ["wg", "set", "dropjak0", "peer", public, "remove"], calls
        )
        self.assertFalse(any(
            "allowed-ips" in call for call in calls
        ))

    def test_failure_is_isolated(self) -> None:
        manager, _ = self.manager(
            lambda args, input: OSError("no ip")
        )
        self.assertFalse(manager.reconcile(tunnels(agents=[agent()])))
        self.assertTrue(manager.error)
        # After the failure the portal keeps working; status is available.
        status = manager.status(tunnels(agents=[agent()]))
        self.assertEqual(status["agents"][0]["online"], False)

    def test_generate_keys_uses_stdin(self) -> None:
        private = key(b"r")
        public = key(b"p")
        psk = key(b"s")

        def handler(args, input):
            if args[-1] == "genkey":
                return 0, private + "\n", ""
            if args[-1] == "pubkey":
                self.assertEqual(input, private + "\n")
                return 0, public + "\n", ""
            return 0, psk + "\n", ""

        manager, runner = self.manager(handler)
        keys = manager.generate_keys()
        self.assertEqual(keys, {
            "private_key": private, "public_key": public,
            "preshared_key": psk,
        })
        pubkey = [
            call for call in runner.calls if call[0] == ["wg", "pubkey"]
        ]
        self.assertEqual(len(pubkey), 1)
        self.assertEqual(pubkey[0][1], private + "\n")

    def test_status_parsing(self) -> None:
        public = key(b"p")
        other = key(b"o")

        def handler(args, input):
            if args[-1] == "latest-handshakes":
                return 0, (
                    f"{public}\t900\n{other}\t1\nbadline\n"
                ), ""
            return 0, f"{public}\t100\t200\n", ""

        manager, _ = self.manager(handler)
        status = manager.status(
            tunnels(agents=[agent(public_key=public)]), now=1000.0
        )
        row = status["agents"][0]
        self.assertTrue(row["online"])
        self.assertEqual(row["last_handshake"], 900)
        self.assertEqual(row["rx_bytes"], 100)
        self.assertEqual(row["tx_bytes"], 200)
        # A handshake older than 180 seconds is offline.
        status = manager.status(
            tunnels(agents=[agent(public_key=public)]), now=2000.0
        )
        self.assertFalse(status["agents"][0]["online"])
        # Without agents there is no wg call.
        _, runner = self.manager(handler)
        status = manager.status(settings_store.default_tunnels())
        self.assertEqual(status["agents"], [])
        self.assertEqual(runner.calls, [])

    def test_remove_all(self) -> None:
        calls: list[str] = []

        def handler(args, input):
            if args[:4] == ["wg", "show", "dropjak0", "peers"]:
                return 0, "A\nB\n", ""
            calls.append(" ".join(args))
            return 0, "", ""

        manager, _ = self.manager(handler)
        manager.remove_all()
        self.assertIn("wg set dropjak0 peer A remove", calls)
        self.assertIn("wg set dropjak0 peer B remove", calls)
        self.assertEqual(manager.error, "")


def _solve(challenge: dict) -> dict:
    import hashlib

    zeros = "0" * int(challenge["difficulty"])
    number = 0
    while True:
        digest = hashlib.sha256(
            f'{challenge["salt"]}{number}'.encode()
        ).hexdigest()
        if digest.startswith(zeros):
            return {**challenge, "number": number}
        number += 1


class FakeTunnelManager:
    """Agent manager without wg/ip for the API tests."""

    def __init__(self) -> None:
        self.error = ""
        self.counter = 0
        self.reconciled: list[dict] = []
        self.removed = 0

    def generate_keys(self) -> dict:
        self.counter += 1
        return {
            "private_key": key(bytes([self.counter])),
            "public_key": key(bytes([self.counter + 40])),
            "preshared_key": key(bytes([self.counter + 80])),
        }

    def reconcile(self, state: dict) -> bool:
        self.reconciled.append(state)
        return True

    def status(self, state: dict, now=None) -> dict:
        return {
            "error": self.error,
            "agents": [
                {
                    "id": item["id"], "online": bool(item.get("enabled")),
                    "last_handshake": 1234, "rx_bytes": 10, "tx_bytes": 20,
                }
                for item in state.get("agents", [])
            ],
        }

    def remove_all(self) -> None:
        self.removed += 1


class TunnelHttpTests(unittest.TestCase):
    """Admin operations, config download and agent sync."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls._old_difficulty = gateway.POW_DIFFICULTY
        cls._old_portal_url = gateway.PORTAL_URL
        gateway.POW_DIFFICULTY = 2
        gateway.PORTAL_URL = ""
        cls.audit = gateway.AuditLog(
            os.path.join(cls.tmp.name, "audit.jsonl"),
            logger=lambda *_: None,
        )
        cls.users = gateway.UserStore(
            os.path.join(cls.tmp.name, "users.json"), iterations=10_000
        )
        cls.rules = gateway.RuleStore(
            os.path.join(cls.tmp.name, "rules.json"),
            catalog=gateway.ServiceCatalog.load(str(ROOT / "services.json")),
            logger=lambda *_: None,
        )
        cls.groups = gateway.GroupStore(
            os.path.join(cls.tmp.name, "groups.json"), logger=lambda *_: None
        )
        cls.fw = gateway.Firewall(
            dry_run=True, logger=lambda *_: None,
            lan_if="eth1", wan_if="eth0",
        )
        cls.settings = settings_store.SettingsStore(
            os.path.join(cls.tmp.name, "settings.json"),
            logger=lambda *_: None,
        )
        cls.certs = settings_store.CertStore(
            os.path.join(cls.tmp.name, "certs")
        )
        cls.drops = gateway.droplog.DropLogService(
            os.path.join(cls.tmp.name, "drops.jsonl"),
            enabled=False, logger=lambda *_: None,
        )
        cls.fail2ban = fail2ban_mod.Fail2ban(
            cls.fw,
            path=os.path.join(cls.tmp.name, "fail2ban.json"),
            audit=cls.audit, logger=lambda *_: None, enabled=False,
        )
        cls.gw = gateway.Gateway(
            users=cls.users, firewall=cls.fw, rules=cls.rules,
            groups=cls.groups, audit=cls.audit, settings=cls.settings,
            certs=cls.certs, drops=cls.drops, fail2ban=cls.fail2ban,
            rate_limiter=gateway.RateLimiter(window=60, maximum=1000),
        )
        server.LOGIN_TICKETS.set_audit(cls.audit)
        cls.app = server.AppServer(("127.0.0.1", 0), cls.gw)
        cls.thread = threading.Thread(
            target=cls.app.serve_forever, daemon=True
        )
        cls.thread.start()
        cls.port = cls.app.server_address[1]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.app.shutdown()
        cls.app.server_close()
        cls.thread.join(timeout=5)
        server.LOGIN_TICKETS.revoke_all(reason="test")
        server.LOGIN_TICKETS.set_audit(None)
        gateway.POW_DIFFICULTY = cls._old_difficulty
        gateway.PORTAL_URL = cls._old_portal_url
        cls.tmp.cleanup()

    def setUp(self) -> None:
        self.gw.sessions.shutdown(reason="test")
        server.LOGIN_TICKETS.revoke_all(reason="test")
        self.gw.users.reset()
        self.gw.users.add("root", "root-jelszo-1", role=gateway.ROLE_ADMIN)
        self.gw.rules.reset()
        self.gw.groups.reset()
        self.gw.settings.reset()
        self.gw.fail2ban.reset()
        self.gw.certs.reset()
        self.gw.tunnel_sync_times.clear()
        self.gw.tunnels = FakeTunnelManager()
        self.restart_calls: list[float] = []

    # -- HTTP helpers ---------------------------------------------------------

    def get(self, path: str, cookie: str = "", source: str = "127.0.0.1",
            headers: dict | None = None):
        import http.client

        conn = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=10, source_address=(source, 0)
        )
        values = dict(headers or {})
        if cookie:
            values["Cookie"] = cookie
        conn.request("GET", path, headers=values)
        response = conn.getresponse()
        body = response.read()
        out = (response.status, dict(response.getheaders()), body)
        conn.close()
        return out

    def post(self, path: str, obj: dict, cookie: str = "",
             source: str = "127.0.0.1", headers: dict | None = None):
        import http.client

        conn = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=10, source_address=(source, 0)
        )
        values = {"Content-Type": "application/json"}
        values.update(headers or {})
        if cookie:
            values["Cookie"] = cookie
        conn.request("POST", path, body=json.dumps(obj), headers=values)
        response = conn.getresponse()
        body = response.read()
        out = (response.status, dict(response.getheaders()), body)
        conn.close()
        return out

    def admin_post(self, path: str, obj: dict, cookie: str = ""):
        return self.post(path, obj, cookie=cookie, source="127.0.0.5")

    def admin_cookie(self) -> str:
        _, _, body = self.get("/api/challenge", source="127.0.0.5")
        challenge = json.loads(body)
        status, headers, body = self.post(
            "/api/login",
            {"user": "root", "pass": "root-jelszo-1",
             "captcha": _solve(challenge)},
            source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        return headers["Set-Cookie"].split(";", 1)[0]

    def admin(self) -> tuple[str, dict]:
        cookie = self.admin_cookie()
        status, _, body = self.get(
            "/api/admin/state", cookie=cookie, source="127.0.0.5"
        )
        self.assertEqual(status, 200, body)
        return cookie, json.loads(body)

    def seed(self, agents, **over) -> None:
        self.gw.settings.commit({"tunnels": tunnels(agents=agents, **over)})

    def tcp_listener(self) -> int:
        """Port of a local TCP listener; closed at the end of the test."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        self.addCleanup(listener.close)
        return listener.getsockname()[1]

    def udp_listener(self) -> int:
        """Port of a local UDP listener that does not answer the probe."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind(("127.0.0.1", 0))
        self.addCleanup(listener.close)
        return listener.getsockname()[1]

    def free_port(self, kind: str = "tcp") -> int:
        """A momentarily free local port (closed immediately after binding)."""
        probe = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM,
        )
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        return port

    def test_tunnel_service_test_requires_admin(self) -> None:
        status, _, _ = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_service_test", "agent_id": "home",
             "service_id": "mc"},
        )
        self.assertEqual(status, 403)

    def proxy_target(self, host: str):
        """Handler._proxy_target decision with the running server's gw."""
        handler = object.__new__(server.Handler)
        handler.server = self.app
        return handler._proxy_target(host)

    # -- state and admin operations ------------------------------------------

    def test_state_hides_secrets_and_shows_status(self) -> None:
        self.seed([agent(services=[service()])])
        _, state = self.admin()
        self.assertNotIn("tunnels", state["settings"])
        item = state["tunnels"]["agents"][0]
        self.assertEqual(item["address"], "10.77.0.2")
        self.assertTrue(item["online"])
        self.assertEqual(item["last_handshake"], 1234)
        self.assertEqual(item["rx_bytes"], 10)
        self.assertEqual(item["config_url"],
                         "/api/admin/tunnels/home/config")
        self.assertEqual(item["bundle_url"],
                         "/api/admin/tunnels/home/bundle")
        self.assertEqual(len(item["services"]), 1)
        text = json.dumps(state)
        for secret in (KEY_A, KEY_B, KEY_C, TOKEN):
            self.assertNotIn(secret, text)

    def test_tunnel_status_endpoint_requires_admin(self) -> None:
        status, _, _ = self.get("/api/admin/tunnels/status")
        self.assertEqual(status, 403)

    def test_tunnel_status_endpoint_read_only_and_last_sync(self) -> None:
        self.seed([agent(services=[service()])])
        cookie = self.admin_cookie()
        before = self.gw.settings.snapshot()
        reconciled = list(self.gw.tunnels.reconciled)
        self.gw.tunnel_sync_times["home"] = time.monotonic() - 5

        status, _, body = self.get(
            "/api/admin/tunnels/status", cookie=cookie, source="127.0.0.5"
        )
        self.assertEqual(status, 200, body)
        payload = json.loads(body)
        self.assertTrue(payload["ok"])
        self.assertLess(
            abs(int(payload["checked_at"]) - int(time.time())), 5
        )
        row = payload["tunnels"]["agents"][0]
        self.assertEqual(row["id"], "home")
        self.assertGreaterEqual(row["last_sync"], 4)
        self.assertLessEqual(row["last_sync"], 7)
        # The endpoint is read-only: the settings and the nft/WireGuard state
        # remain unchanged.
        self.assertEqual(self.gw.settings.snapshot(), before)
        self.assertEqual(self.gw.tunnels.reconciled, reconciled)

        # For a never-synced agent the field is None.
        self.gw.tunnel_sync_times.clear()
        status, _, body = self.get(
            "/api/admin/tunnels/status", cookie=cookie, source="127.0.0.5"
        )
        self.assertEqual(status, 200, body)
        row = json.loads(body)["tunnels"]["agents"][0]
        self.assertIsNone(row["last_sync"])

    def test_tunnel_settings_saved(self) -> None:
        cookie = self.admin_cookie()
        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_settings", "port": 51999,
             "endpoint": "cloud.example.com"},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        saved = self.gw.settings.snapshot()["tunnels"]
        self.assertEqual(saved["port"], 51999)
        self.assertEqual(saved["endpoint"], "cloud.example.com")
        payload = json.loads(body)
        self.assertEqual(payload["tunnels"]["port"], 51999)

    def test_agent_and_service_lifecycle(self) -> None:
        self.seed([])
        cookie, state = self.admin()
        self.assertEqual(state["tunnels"]["agents"], [])

        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_agent_add", "label": "Otthon"},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        payload = json.loads(body)
        agent_id = payload["agent_id"]
        added = payload["tunnels"]["agents"][0]
        self.assertEqual(added["id"], agent_id)
        self.assertEqual(added["address"], "10.77.0.2")
        self.assertTrue(added["online"])
        stored = self.gw.settings.snapshot()["tunnels"]
        self.assertTrue(stored["server_private_key"])
        self.assertTrue(stored["server_public_key"])
        self.assertNotEqual(stored["agents"][0]["private_key"], "")

        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_agent_add", "label": "Iroda"},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            json.loads(body)["tunnels"]["agents"][1]["address"],
            "10.77.0.3",
        )

        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_agent_update", "id": agent_id,
             "label": "Otthon (off)", "enabled": False},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        updated = json.loads(body)["tunnels"]["agents"][0]
        self.assertFalse(updated["enabled"])
        self.assertEqual(updated["label"], "Otthon (off)")

        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_service_save", "agent_id": agent_id,
             "label": "Minecraft", "target_host": "mc", "enabled": True,
             "mappings": [
                 {"proto": "both", "listen": "25565", "target": "25565"},
             ]},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        payload = json.loads(body)
        service_id = payload["service_id"]
        service_row = payload["tunnels"]["agents"][0]["services"][0]
        self.assertEqual(service_row["id"], service_id)
        self.assertEqual(service_row["target_host"], "mc")
        self.assertEqual(service_row["mappings"], [
            {"proto": "both", "listen": "25565", "target": "25565"},
        ])
        self.assertEqual(service_row["ports"], [
            {"proto": "both", "listen_port": 25565, "target_port": 25565},
        ])
        self.assertNotIn("tunnel_port", service_row)

        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_service_save", "agent_id": agent_id,
             "label": "Web", "target_host": "web", "enabled": True,
             "mappings": [
                 {"proto": "tcp", "listen": "8080", "target": "80"},
             ]},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        web_row = json.loads(body)["tunnels"]["agents"][0]["services"][1]
        self.assertEqual(web_row["ports"], [
            {"proto": "tcp", "listen_port": 8080, "target_port": 80},
        ])

        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_service_save", "agent_id": agent_id,
             "id": service_id, "label": "Minecraft", "target_host": "mc",
             "enabled": False, "mappings": [
                 {"proto": "both", "listen": "25565", "target": "25565"},
             ]},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        self.assertFalse(
            json.loads(body)["tunnels"]["agents"][0]["services"][0]
            ["enabled"]
        )

        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_service_delete", "agent_id": agent_id,
             "id": service_id},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            len(json.loads(body)["tunnels"]["agents"][0]["services"]), 1
        )

        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_agent_delete", "id": agent_id},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            len(json.loads(body)["tunnels"]["agents"]), 1
        )

    def test_validation_errors_have_field(self) -> None:
        self.seed([agent()])
        cookie, _ = self.admin()
        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_service_save", "agent_id": "home",
             "label": "SSH", "target_host": "box", "enabled": True,
             "mappings": [
                 {"proto": "tcp", "listen": "22", "target": "22"},
             ]},
            cookie=cookie,
        )
        self.assertEqual(status, 400, body)
        error = json.loads(body)
        self.assertFalse(error["ok"])
        self.assertEqual(error["field"], "listen_port")
        self.assertIn("reserved", error["error"])

        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_agent_update", "id": "nincs",
             "enabled": True},
            cookie=cookie,
        )
        self.assertEqual(status, 400, body)
        self.assertEqual(json.loads(body)["field"], "agents")

        # The port proxy and the tunnel share one listen-port namespace.
        self.gw.settings.commit({
            "port_proxies": [proxy_entry()],
            "tunnels": tunnels(agents=[agent()]),
        })
        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_service_save", "agent_id": "home",
             "label": "Minecraft", "target_host": "mc", "enabled": True,
             "mappings": [
                 {"proto": "tcp", "listen": "25565", "target": "25565"},
             ]},
            cookie=cookie,
        )
        self.assertEqual(status, 400, body)
        self.assertEqual(json.loads(body)["field"], "listen_port")

    def test_tunnel_actions_require_admin(self) -> None:
        status, _, _ = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_agent_add", "label": "Otthon"},
        )
        self.assertEqual(status, 403)
        status, _, _ = self.get("/api/admin/tunnels/home/config")
        self.assertEqual(status, 403)

    def test_service_test_rejects_unknown_and_disabled(self) -> None:
        cookie = self.admin_cookie()

        def post(payload):
            return self.admin_post(
                "/api/admin/settings", payload, cookie=cookie
            )

        status, _, body = post({
            "action": "tunnel_service_test", "agent_id": "nincs",
            "service_id": "mc",
        })
        self.assertEqual(status, 404, body)
        self.assertEqual(json.loads(body)["error"], "tunnel: no such agent")

        self.seed([agent(services=[service()])])
        status, _, body = post({
            "action": "tunnel_service_test", "agent_id": "home",
            "service_id": "nincs",
        })
        self.assertEqual(status, 404, body)
        self.assertEqual(
            json.loads(body)["error"], "tunnel: no such service"
        )

        self.seed([agent(enabled=False, services=[service()])])
        status, _, body = post({
            "action": "tunnel_service_test", "agent_id": "home",
            "service_id": "mc",
        })
        self.assertEqual(status, 409, body)
        self.assertEqual(
            json.loads(body)["error"], "tunnel: the agent is disabled"
        )

        self.seed([agent(services=[service(enabled=False)])])
        status, _, body = post({
            "action": "tunnel_service_test", "agent_id": "home",
            "service_id": "mc",
        })
        self.assertEqual(status, 409, body)
        self.assertEqual(
            json.loads(body)["error"],
            "tunnel: the service is disabled",
        )

        status, _, body = post({
            "action": "tunnel_service_test", "agent_id": "home",
        })
        self.assertEqual(status, 400, body)

    def test_service_test_tcp_success_is_read_only_and_audited(self) -> None:
        port = self.tcp_listener()
        self.seed([agent(services=[
            service(mappings=[mapping("tcp", str(port), "25565")]),
        ])])
        cookie, _ = self.admin()
        before = self.gw.settings.snapshot()
        reconciled = len(self.gw.tunnels.reconciled)
        with mock.patch.object(
            server.Handler, "_tunnel_test_address",
            lambda _self, _agent: "127.0.0.1",
        ):
            status, _, body = self.admin_post(
                "/api/admin/settings",
                {"action": "tunnel_service_test", "agent_id": "home",
                 "service_id": "mc"},
                cookie=cookie,
            )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["service"]["id"], "mc")
        self.assertEqual(data["results"], [{
            "proto": "tcp", "listen": port, "target": "mc:25565",
            "ok": True, "detail": "connection established",
        }])
        self.assertEqual(data["summary"], "service reachable")
        # The test writes no settings and applies no nftables rule.
        self.assertEqual(before, self.gw.settings.snapshot())
        self.assertEqual(reconciled, len(self.gw.tunnels.reconciled))
        # The audit contains only identifiers, ports and result flags.
        entries = []
        with open(self.audit.path, encoding="utf-8") as fh:
            for line in fh:
                row = json.loads(line)
                if row.get("event") == "tunnel_service_test":
                    entries.append(row)
        self.assertTrue(entries)
        last = entries[-1]
        self.assertEqual(last["agent_id"], "home")
        self.assertEqual(last["service_id"], "mc")
        self.assertEqual(last["listen_ports"], str(port))
        self.assertEqual(last["target_ports"], "25565")
        self.assertEqual(last["ok"], "1")
        text = json.dumps(entries)
        stored = self.gw.settings.snapshot()["tunnels"]
        for secret in (
            KEY_A, KEY_B, KEY_C, TOKEN,
            stored["server_private_key"], stored["server_public_key"],
        ):
            self.assertNotIn(secret, text)

    def test_service_test_tcp_refused_and_timeout(self) -> None:
        port = self.free_port("tcp")
        self.seed([agent(services=[
            service(mappings=[mapping("tcp", str(port), "25565")]),
        ])])
        cookie, _ = self.admin()
        with mock.patch.object(
            server.Handler, "_tunnel_test_address",
            lambda _self, _agent: "127.0.0.1",
        ):
            status, _, body = self.admin_post(
                "/api/admin/settings",
                {"action": "tunnel_service_test", "agent_id": "home",
                 "service_id": "mc"},
                cookie=cookie,
            )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertFalse(data["results"][0]["ok"])
        self.assertEqual(data["results"][0]["detail"], "refused")
        self.assertIn("service unreachable", data["summary"])

        # Deterministic timeout: we replace the probe itself, so the short
        # test does not depend on how the network is unreachable.
        with mock.patch.object(
            server.Handler, "_tunnel_test_address",
            lambda _self, _agent: "127.0.0.1",
        ), mock.patch.object(
            server.Handler, "_tunnel_probe_tcp",
            staticmethod(lambda _a, _p: {
                "ok": False, "detail": "timeout",
            }),
        ):
            status, _, body = self.admin_post(
                "/api/admin/settings",
                {"action": "tunnel_service_test", "agent_id": "home",
                 "service_id": "mc"},
                cookie=cookie,
            )
        self.assertEqual(status, 200, body)
        row = json.loads(body)["results"][0]
        self.assertFalse(row["ok"])
        self.assertEqual(row["detail"], "timeout")

    def test_service_test_udp_no_reply_and_icmp_refused(self) -> None:
        silent = self.udp_listener()
        refused = self.free_port("udp")
        self.seed([agent(services=[
            service(service_id="udp", target_host="mc", mappings=[
                mapping("udp", str(silent), "25565"),
            ]),
            service(service_id="icmp", target_host="mc", mappings=[
                mapping("udp", str(refused), "25565"),
            ]),
        ])])
        cookie, _ = self.admin()
        with mock.patch.object(
            server.Handler, "_tunnel_test_address",
            lambda _self, _agent: "127.0.0.1",
        ):
            status, _, body = self.admin_post(
                "/api/admin/settings",
                {"action": "tunnel_service_test", "agent_id": "home",
                 "service_id": "udp"},
                cookie=cookie,
            )
            self.assertEqual(status, 200, body)
            data = json.loads(body)
            self.assertTrue(data["results"][0]["ok"])
            self.assertEqual(
                data["results"][0]["detail"],
                "sent, no UDP reply expected",
            )
            self.assertEqual(data["summary"], "service reachable")

            status, _, body = self.admin_post(
                "/api/admin/settings",
                {"action": "tunnel_service_test", "agent_id": "home",
                 "service_id": "icmp"},
                cookie=cookie,
            )
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        self.assertFalse(data["results"][0]["ok"])
        self.assertEqual(data["results"][0]["detail"], "refused (ICMP)")
        self.assertIn("service unreachable", data["summary"])

    def test_service_test_caps_mappings_and_runs_concurrently(self) -> None:
        ports = [self.free_port("tcp") for _ in range(5)]
        self.seed([agent(services=[
            service(mappings=[
                mapping("tcp", str(port), "25565") for port in ports
            ]),
        ])])
        cookie, _ = self.admin()

        calls: list[int] = []

        def slow(_address, port):
            calls.append(port)
            time.sleep(0.4)
            return {"ok": True, "detail": "connection established"}

        with mock.patch.object(
            server.Handler, "_tunnel_test_address",
            lambda _self, _agent: "127.0.0.1",
        ), mock.patch.object(
            server.Handler, "_tunnel_probe_tcp", staticmethod(slow),
        ):
            started = time.monotonic()
            status, _, body = self.admin_post(
                "/api/admin/settings",
                {"action": "tunnel_service_test", "agent_id": "home",
                 "service_id": "mc"},
                cookie=cookie,
            )
            elapsed = time.monotonic() - started
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        # At most four mappings; the response indicates the rest.
        self.assertEqual(len(data["results"]), 4)
        self.assertEqual(len(calls), 4)
        self.assertIn("only the first 4 mappings", data["summary"])
        # They run concurrently: four 0.4 s probes finish well under 1.6 s.
        self.assertLess(elapsed, 1.2)


    def test_audit_never_contains_keys_or_tokens(self) -> None:
        cookie = self.admin_cookie()
        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_agent_add", "label": "Otthon"},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        stored = self.gw.settings.snapshot()["tunnels"]
        row = stored["agents"][0]
        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_service_save", "agent_id": row["id"],
             "label": "Minecraft", "target_host": "mc", "enabled": True,
             "mappings": [
                 {"proto": "tcp", "listen": "25565", "target": "25565"},
             ]},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        with open(self.audit.path, encoding="utf-8") as fh:
            text = fh.read()
        for secret in (
            row["private_key"], row["public_key"], row["preshared_key"],
            row["token"], stored["server_private_key"],
            stored["server_public_key"],
        ):
            self.assertNotIn(secret, text)

    # -- agent config and sync -----------------------------------------------

    def test_config_download_contents_and_headers(self) -> None:
        self.seed(
            [agent(services=[
                service(),
                service(service_id="off", enabled=False, target_host="web",
                        mappings=[mapping("tcp", "8081", "81")]),
            ])],
            endpoint="cloud.example.com",
        )
        cookie, _ = self.admin()
        status, headers, body = self.get(
            "/api/admin/tunnels/home/config",
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body[:300])
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        self.assertEqual(
            headers.get("Content-Disposition"),
            'attachment; filename="dropjak-agent-home.json"',
        )
        config = json.loads(body)
        self.assertEqual(config["format"], "dropjak-agent")
        self.assertEqual(config["version"], 1)
        self.assertEqual(config["agent"], {
            "id": "home", "label": "Otthon", "address": "10.77.0.2",
        })
        wireguard = config["wireguard"]
        self.assertEqual(wireguard["private_key"], KEY_A)
        self.assertEqual(wireguard["address"], "10.77.0.2/24")
        self.assertEqual(wireguard["peer_public_key"], KEY_B)
        self.assertEqual(wireguard["preshared_key"], KEY_C)
        self.assertEqual(wireguard["endpoint"], "cloud.example.com:51820")
        self.assertEqual(wireguard["allowed_ips"], ["10.77.0.1/32"])
        self.assertEqual(wireguard["persistent_keepalive"], 25)
        self.assertEqual(config["sync"]["token"], TOKEN)
        self.assertEqual(
            config["sync"]["url"],
            "http://10.77.0.1:"
            f"{settings_store.TUNNEL_SYNC_PORT}/api/tunnel/config",
        )
        self.assertEqual(config["sync"]["interval_seconds"], 30)
        self.assertEqual(config["services"], [{
            "id": "p25565", "label": "Minecraft", "proto": "tcp",
            "tunnel_port": 25565, "target": "mc:25565", "enabled": True,
        }])
        self.assertIs(config["services"][0]["enabled"], True)

    def test_config_and_sync_expand_ranges_and_merge_both(self) -> None:
        self.seed([agent(services=[
            service(mappings=[
                mapping("tcp", "8000-8001", "18000-18001"),
            ]),
            service(service_id="voice", mappings=[
                mapping("udp", "8000-8001", "18000-18001"),
            ]),
        ])])
        cookie, _ = self.admin()
        status, _, body = self.get(
            "/api/admin/tunnels/home/config",
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body[:300])
        services = json.loads(body)["services"]
        self.assertEqual([s["id"] for s in services], ["p8000", "p8001"])
        self.assertEqual([s["proto"] for s in services], ["both", "both"])
        self.assertEqual([s["tunnel_port"] for s in services], [8000, 8001])
        self.assertEqual(
            [s["target"] for s in services], ["mc:18000", "mc:18001"]
        )
        with mock.patch.object(
            server.Handler, "_peer_ip", return_value="10.77.0.2"
        ):
            status, _, body = self.get(
                "/api/tunnel/config",
                headers={"Authorization": f"Bearer {TOKEN}"},
            )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["services"], services)

    def test_bundle_download_is_a_self_contained_installer(self) -> None:
        import io
        import tarfile

        self.seed([agent(services=[service()])],
                  endpoint="cloud.example.com")
        cookie, _ = self.admin()
        status, headers, body = self.get(
            "/api/admin/tunnels/home/bundle",
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body[:300])
        self.assertEqual(headers.get("Content-Type"), "application/x-sh")
        self.assertEqual(
            headers.get("Content-Disposition"),
            'attachment; filename="dropjak-agent-home.sh"',
        )
        # The digest the admin compares with the installer's banner (DJ-08).
        import hashlib

        digest = hashlib.sha256(body).hexdigest()
        self.assertEqual(headers.get("X-Dropjak-SHA256"), digest)
        downloads = [
            json.loads(line) for line in Path(
                self.tmp.name, "audit.jsonl").read_text().splitlines()
            if '"tunnel_agent_config_downloaded"' in line
        ]
        self.assertEqual(downloads[-1].get("sha256"), digest)
        # A single file: a shell prefix, then the tar.gz package.
        marker = b"__DROPJAK_PAYLOAD__\n"
        self.assertTrue(body.startswith(b"#!/bin/sh\n"), body[:20])
        split = body.index(marker) + len(marker)
        header, payload = body[:split], body[split:]
        self.assertIn(b"docker compose up -d --build", header)
        self.assertIn(b"agent.json", header)
        self.assertEqual(
            header,
            (ROOT / "deploy" / "tunnel-agent" / "selfinstall.sh").read_bytes(),
        )
        # The script header is valid sh syntax (without the binary trailer).
        check = subprocess.run(
            ["sh", "-n"], input=header, capture_output=True, timeout=10,
        )
        self.assertEqual(check.returncode, 0, check.stderr)
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar:
            members = {m.name: m for m in tar.getmembers()}
            self.assertEqual(
                set(members),
                {"compose.yml", "agent.json", "Dockerfile", "agent.py",
                 "check-containment.sh"},
            )
            self.assertEqual(members["agent.json"].mode, 0o600)
            self.assertEqual(members["agent.py"].mode, 0o755)
            config = json.loads(tar.extractfile("agent.json").read())
            compose = tar.extractfile("compose.yml").read().decode()
            agent_py = tar.extractfile("agent.py").read()
        self.assertEqual(config["wireguard"]["private_key"], KEY_A)
        self.assertEqual(config["services"][0]["id"], "p25565")
        self.assertEqual(config["services"][0]["tunnel_port"], 25565)
        self.assertEqual(compose.count("external: true"), 1)
        self.assertIn('name: "playitgg-net"', compose)
        self.assertNotIn("host.docker.internal", compose)
        self.assertNotIn("internal: true", compose)
        self.assertNotIn("egress", compose)
        # The package's static template contains a fixed example name; the installer
        # derives the real name from agent.json at run time.
        self.assertIn("container_name: dropjak-tunnel-agent-home-home-1",
                      compose)
        self.assertIn("dropjak-tunnel-agent-<label-slug>-<id>", compose)
        self.assertIn("./agent.json:/etc/dropjak/agent.json:ro,Z", compose)
        self.assertEqual(
            agent_py,
            (ROOT / "deploy" / "tunnel-agent" / "agent.py").read_bytes(),
        )
        # The same permissions as at the Config endpoint.
        status, _, _ = self.get("/api/admin/tunnels/home/bundle")
        self.assertEqual(status, 403)
        status, _, _ = self.get(
            "/api/admin/tunnels/nincs/bundle",
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 404)

    def test_config_endpoint_falls_back_to_host(self) -> None:
        self.seed([agent()])
        cookie, _ = self.admin()
        status, _, body = self.get(
            "/api/admin/tunnels/home/config",
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body[:300])
        endpoint = json.loads(body)["wireguard"]["endpoint"]
        self.assertTrue(endpoint.startswith("127.0.0.1:"), endpoint)
        self.assertTrue(endpoint.endswith(":51820"), endpoint)

    def test_config_download_unknown_agent(self) -> None:
        cookie, _ = self.admin()
        status, _, _ = self.get(
            "/api/admin/tunnels/nincs/config",
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 404)

    def test_sync_requires_source_ip_and_token(self) -> None:
        self.seed([agent(services=[service()])])
        path = "/api/tunnel/config"
        with mock.patch.object(
            server.Handler, "_peer_ip", return_value="10.77.0.2"
        ):
            status, headers, body = self.get(
                path, headers={"Authorization": f"Bearer {TOKEN}"}
            )
        self.assertEqual(status, 200, body)
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        payload = json.loads(body)
        self.assertEqual(payload["agent"], {"id": "home", "label": "Otthon"})
        self.assertEqual(payload["services"], [{
            "id": "p25565", "label": "Minecraft", "proto": "tcp",
            "tunnel_port": 25565, "target": "mc:25565", "enabled": True,
        }])
        self.assertNotIn(TOKEN, body.decode())

        with mock.patch.object(
            server.Handler, "_peer_ip", return_value="10.77.0.2"
        ):
            status, _, _ = self.get(
                path, headers={"Authorization": "Bearer wrong"}
            )
        self.assertEqual(status, 403)
        with mock.patch.object(
            server.Handler, "_peer_ip", return_value="10.77.0.99"
        ):
            status, _, _ = self.get(
                path, headers={"Authorization": f"Bearer {TOKEN}"}
            )
        self.assertEqual(status, 403)
        with mock.patch.object(
            server.Handler, "_peer_ip", return_value="10.77.0.2"
        ):
            status, _, _ = self.get(path)
        self.assertEqual(status, 403)

    def test_tunnel_peer_reaches_only_the_sync_endpoint(self) -> None:
        self.seed([agent(services=[service()])])
        with mock.patch.object(
            server.Handler, "_peer_ip", return_value="10.77.0.2"
        ):
            for path in (
                "/", "/api/status", "/api/challenge", "/api/admin/state",
                "/api/admin/fail2ban", "/api/tunnel/config/../status",
            ):
                with self.subTest(path=path):
                    status, _, body = self.get(
                        path, headers={"Authorization": f"Bearer {TOKEN}"}
                    )
                    self.assertEqual(status, 404, body)
            for path in ("/api/login", "/api/register", "/api/tunnel/config"):
                with self.subTest(path=path):
                    status, _, _ = self.post(
                        path, {"user": "root", "pass": "root-jelszo-1"}
                    )
                    self.assertEqual(status, 404)
            # The one endpoint an agent needs still works.
            status, _, body = self.get(
                "/api/tunnel/config",
                headers={"Authorization": f"Bearer {TOKEN}"},
            )
            self.assertEqual(status, 200, body)
        # Outside the tunnel network nothing changes.
        status, _, _ = self.get("/api/status")
        self.assertEqual(status, 200)

    def test_sync_disabled_agent_rejected(self) -> None:
        self.seed([agent(enabled=False)])
        with mock.patch.object(
            server.Handler, "_peer_ip", return_value="10.77.0.2"
        ):
            status, _, _ = self.get(
                "/api/tunnel/config",
                headers={"Authorization": f"Bearer {TOKEN}"},
            )
        self.assertEqual(status, 403)

    def test_sync_rate_limited_per_agent(self) -> None:
        self.seed([agent()])
        with mock.patch.object(
            server.Handler, "_peer_ip", return_value="10.77.0.2"
        ):
            status, _, _ = self.get(
                "/api/tunnel/config",
                headers={"Authorization": f"Bearer {TOKEN}"},
            )
            self.assertEqual(status, 200)
            status, headers, _ = self.get(
                "/api/tunnel/config",
                headers={"Authorization": f"Bearer {TOKEN}"},
            )
        self.assertEqual(status, 429)
        self.assertEqual(headers.get("Retry-After"), "5")
        # After some time it can be served again.
        self.gw.tunnel_sync_times["home"] = (
            time.monotonic() - tunnel_mod.ONLINE_SECONDS
        )
        with mock.patch.object(
            server.Handler, "_peer_ip", return_value="10.77.0.2"
        ):
            status, _, _ = self.get(
                "/api/tunnel/config",
                headers={"Authorization": f"Bearer {TOKEN}"},
            )
        self.assertEqual(status, 200)

    # -- domain-mode tunnel services ------------------------------------------

    def prepare_domain(self, services, domains=("example.com",)) -> None:
        # commit replaces the whole state; the proxy roots must be given in the
        # same step, otherwise the domain-mode service cannot be
        # validated.
        self.gw.settings.commit({
            **self.gw.settings.snapshot(),
            "proxy_domains": list(domains),
            "proxy_routes": [],
            "tunnels": tunnels(agents=[agent(services=services)]),
        })

    def test_domain_names_include_tunnel_services(self) -> None:
        self.prepare_domain([
            domain_service(
                service_id="web", domain="web.example.com",
                mappings=[mapping("tcp", "", "8080")],
            ),
            domain_service(
                service_id="off", domain="off.example.com", enabled=False,
                mappings=[mapping("tcp", "", "8080")],
            ),
        ])
        names = self.gw.rules.domain_names()
        self.assertIn("web.example.com", names)
        # The domain of a disabled service is also visible so that the
        # delete/disable lifecycle guard can refer to it.
        self.assertIn("off.example.com", names)

    def test_domain_target_resolves_only_enabled_services(self) -> None:
        self.prepare_domain([
            domain_service(
                service_id="pub", domain="pub.example.com", public=True,
                mappings=[mapping("tcp", "", "8080")],
            ),
            domain_service(
                service_id="off", domain="off.example.com", enabled=False,
                mappings=[mapping("tcp", "", "8081")],
            ),
        ])
        target, root = self.proxy_target("pub.example.com")
        self.assertEqual(root, "example.com")
        self.assertEqual(target["type"], "forward")
        self.assertEqual(target["ip"], "10.77.0.2")
        self.assertEqual(target["visibility"], "public")
        self.assertTrue(target["tunnel"])
        self.assertGreaterEqual(
            target["port"], settings_store.TUNNEL_DOMAIN_PORT_LOW
        )
        self.assertLessEqual(
            target["port"], settings_store.TUNNEL_DOMAIN_PORT_HIGH
        )
        # A disabled service and an unknown subdomain do not resolve.
        self.assertEqual(
            self.proxy_target("off.example.com"), (None, "")
        )
        self.assertEqual(
            self.proxy_target("unknown.example.com"), (None, "")
        )
        # An agent without a domain yields no match.
        self.gw.settings.reset()
        self.assertIsNone(server._tunnel_domain_target(
            self.gw.settings.snapshot(), "pub.example.com"
        ))

    def test_domain_target_carries_challenge(self) -> None:
        challenge = {"triggers": ["always"], "interval_hours": 24}
        self.prepare_domain([
            domain_service(
                service_id="pub", domain="pub.example.com", public=True,
                mappings=[mapping("tcp", "", "8080")], challenge=challenge,
            ),
            domain_service(
                service_id="plain", domain="plain.example.com", public=True,
                mappings=[mapping("tcp", "", "8081")],
            ),
        ])
        target, _ = self.proxy_target("pub.example.com")
        self.assertEqual(target["challenge"], challenge)
        plain, _ = self.proxy_target("plain.example.com")
        self.assertNotIn("challenge", plain)
        # A public target's challenge redirects the request to a captcha page.
        status, _, body = self.get("/api/proxy/auth", headers={
            "X-Forwarded-Host": "pub.example.com",
            "X-Forwarded-For": "203.0.113.10",
            "X-Forwarded-Uri": "/",
        })
        self.assertEqual(status, 403)
        self.assertIn(b"proxy_challenge", body)

    def test_ask_public_and_unknown_domain(self) -> None:
        self.prepare_domain([
            domain_service(
                service_id="pub", domain="pub.example.com", public=True,
                mappings=[mapping("tcp", "", "8080")],
            ),
        ])
        status, _, _ = self.get("/api/proxy/ask?domain=pub.example.com")
        self.assertEqual(status, 200)
        status, _, _ = self.get("/api/proxy/ask?domain=missing.example.com")
        self.assertEqual(status, 404)

    def test_auth_public_without_session(self) -> None:
        self.prepare_domain([
            domain_service(
                service_id="pub", domain="pub.example.com", public=True,
                mappings=[mapping("tcp", "", "8080")],
            ),
        ])
        port = self.proxy_target("pub.example.com")[0]["port"]
        status, headers, _ = self.get("/api/proxy/auth", headers={
            "X-Forwarded-Host": "pub.example.com",
            "X-Forwarded-For": "203.0.113.9",
            "X-Forwarded-Uri": "/",
        })
        self.assertEqual(status, 200)
        self.assertEqual(
            headers.get("X-Dropjak-Upstream"), f"10.77.0.2:{port}"
        )

    def test_auth_private_needs_domain_rule_session(self) -> None:
        self.prepare_domain([
            domain_service(
                service_id="priv", domain="priv.example.com",
                mappings=[mapping("tcp", "", "8081")],
            ),
        ])
        port = self.proxy_target("priv.example.com")[0]["port"]
        headers = {
            "X-Forwarded-Host": "priv.example.com",
            "X-Forwarded-For": "203.0.113.9",
            "X-Forwarded-Uri": "/",
        }
        status, _, _ = self.get("/api/proxy/auth", headers=headers)
        self.assertEqual(status, 401)
        now = time.time()
        self.gw.sessions._sessions["203.0.113.9"] = gateway.Session(
            token="session", user="u", ip="203.0.113.9",
            created=now, expires=now + 60, authorized=True,
            role=gateway.ROLE_USER, full=False, grant_parts=(),
            rule_parts=(gateway.RuleSelection(
                "r", "r", (), ("priv.example.com",),
            ),),
        )
        status, response, _ = self.get("/api/proxy/auth", headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(
            response.get("X-Dropjak-Upstream"), f"10.77.0.2:{port}"
        )

    def test_redirect_domain_tunnel_host_is_308(self) -> None:
        self.prepare_domain([
            domain_service(
                service_id="pub", domain="pub.example.com", public=True,
                mappings=[mapping("tcp", "", "8080")],
            ),
        ])
        status, headers, _ = self.get("/api/proxy/redirect", headers={
            "X-Forwarded-Host": "pub.example.com",
            "X-Forwarded-Uri": "/proba?x=1",
        })
        self.assertEqual(status, 308)
        self.assertEqual(
            headers.get("Location"), "https://pub.example.com/proba?x=1"
        )

    def test_domain_service_lifecycle_guards(self) -> None:
        self.prepare_domain([
            domain_service(
                service_id="web", domain="web.example.com",
                mappings=[mapping("tcp", "", "8080")],
            ),
        ])
        self.gw.rules.create("dom", {
            "label": "Web", "domains": ["web.example.com"],
        })
        cookie = self.admin_cookie()

        def post(payload):
            status, _, body = self.admin_post(
                "/api/admin/settings", payload, cookie=cookie
            )
            return status, json.loads(body)

        blocked = [
            {"action": "tunnel_agent_delete", "id": "home"},
            {"action": "tunnel_service_delete", "agent_id": "home",
             "id": "web"},
            {"action": "tunnel_service_save", "agent_id": "home", "id": "web",
             "label": "Web", "target_host": "web", "enabled": True,
             "domain": "", "mappings": [
                 {"proto": "tcp", "listen": "25565", "target": "8080"},
             ]},
            {"action": "tunnel_service_save", "agent_id": "home", "id": "web",
             "label": "Web", "target_host": "web", "enabled": True,
             "domain": "other.example.com", "mappings": [
                 {"proto": "tcp", "listen": "", "target": "8080"},
             ]},
        ]
        for payload in blocked:
            with self.subTest(action=payload["action"]):
                status, body = post(payload)
                self.assertEqual(status, 400, body)
                self.assertIn("a domain rule references it", body["error"])

        # Disabling is always allowed (fail-closed), even with a referencing
        # domain rule; only deletion/domain change is forbidden.
        allowed = [
            {"action": "tunnel_agent_update", "id": "home",
             "enabled": False},
            {"action": "tunnel_agent_update", "id": "home",
             "enabled": True},
            {"action": "tunnel_service_save", "agent_id": "home", "id": "web",
             "label": "Web", "target_host": "web", "enabled": False,
             "domain": "web.example.com", "mappings": [
                 {"proto": "tcp", "listen": "", "target": "8080"},
             ]},
            {"action": "tunnel_service_save", "agent_id": "home", "id": "web",
             "label": "Web", "target_host": "web", "enabled": True,
             "domain": "web.example.com", "mappings": [
                 {"proto": "tcp", "listen": "", "target": "8080"},
             ]},
        ]
        for payload in allowed:
            with self.subTest(action=payload["action"]):
                status, body = post(payload)
                self.assertEqual(status, 200, body)
        # After the referencing rule is deleted, removing the domain is also allowed.
        self.gw.rules.delete("dom")
        status, body = post(blocked[-1])
        self.assertEqual(status, 200, body)

    def test_domain_service_challenge_saved_without_other_changes(self) -> None:
        self.prepare_domain([
            domain_service(
                service_id="web", domain="web.example.com",
                mappings=[mapping("tcp", "", "8080")],
            ),
        ])
        cookie = self.admin_cookie()
        before = self.gw.settings.snapshot()["tunnels"]["agents"][0][
            "services"][0]

        def post(payload):
            status, _, body = self.admin_post(
                "/api/admin/settings", payload, cookie=cookie
            )
            return status, json.loads(body)

        challenge = {"triggers": ["always"], "interval_hours": 24}
        status, body = post({
            "action": "tunnel_service_save", "agent_id": "home", "id": "web",
            "challenge": challenge,
        })
        self.assertEqual(status, 200, body)
        saved = self.gw.settings.snapshot()["tunnels"]["agents"][0][
            "services"][0]
        self.assertEqual(saved["challenge"], challenge)
        # A partial save does not affect the other fields.
        for key in ("label", "target_host", "enabled", "public", "domain",
                    "mappings"):
            self.assertEqual(saved[key], before[key], key)
        target, _ = self.proxy_target("web.example.com")
        self.assertEqual(target["challenge"], challenge)

        # When the domain is removed the challenge is deleted too, and the save
        # does not get stuck on validating a challenge without a domain.
        status, body = post({
            "action": "tunnel_service_save", "agent_id": "home", "id": "web",
            "domain": "", "mappings": [
                {"proto": "tcp", "listen": "25565", "target": "8080"},
            ],
        })
        self.assertEqual(status, 200, body)
        saved = self.gw.settings.snapshot()["tunnels"]["agents"][0][
            "services"][0]
        self.assertEqual(saved["domain"], "")
        self.assertNotIn("challenge", saved)

    # -- config bundle and restore --------------------------------------------

    def test_bundle_roundtrip_and_version_migration(self) -> None:
        self.seed([agent(services=[service()])])
        bundle = server._config_bundle(self.gw)
        self.assertEqual(bundle["format_version"], 2)
        self.assertEqual(
            len(bundle["sections"]["settings"]["tunnels"]["agents"]), 1
        )
        checked = server._validate_config_bundle(
            self.gw, json.loads(json.dumps(bundle))
        )
        self.assertEqual(
            len(checked["settings"]["tunnels"]["agents"][0]["services"]), 1
        )
        counts = server._config_counts(checked)
        self.assertEqual(counts["tunnel_agents"], 1)
        self.assertEqual(counts["tunnel_services"], 1)

        legacy = json.loads(json.dumps(bundle))
        legacy["format_version"] = 1
        legacy["sections"]["settings"].pop("tunnels")
        migrated = server._validate_config_bundle(self.gw, legacy)
        self.assertEqual(
            migrated["settings"]["tunnels"],
            settings_store.default_tunnels(),
        )

        # The old single-port service shape of a version 2 bundle migrates on load.
        old_shape = json.loads(json.dumps(bundle))
        old_shape["sections"]["settings"]["tunnels"]["agents"][0]["services"] = [{
            "id": "mc", "label": "Minecraft", "proto": "tcp",
            "listen_port": 25565, "tunnel_port": 41000,
            "target": "mc:25565", "enabled": True,
        }]
        migrated = server._validate_config_bundle(self.gw, old_shape)
        self.assertEqual(
            migrated["settings"]["tunnels"]["agents"][0]["services"][0],
            {
                "id": "mc", "label": "Minecraft", "target_host": "mc",
                "enabled": True, "public": False, "domain": "",
                "mappings": [
                    {"proto": "tcp", "listen": "25565", "target": "25565"},
                ],
            },
        )

        invalid = json.loads(json.dumps(bundle))
        invalid["sections"]["settings"].pop("tunnels")
        with self.assertRaises(server.ConfigBundleError):
            server._validate_config_bundle(self.gw, invalid)
        bundle["format_version"] = 3
        with self.assertRaises(server.ConfigBundleError):
            server._validate_config_bundle(self.gw, bundle)

    def test_reset_clears_tunnels_and_peers(self) -> None:
        self.seed([agent(services=[service()])])
        cookie = self.admin_cookie()
        fake = self.gw.tunnels
        with mock.patch.object(
            server, "_request_service_restart",
            lambda delay=0.5: self.restart_calls.append(delay),
        ):
            status, _, body = self.admin_post(
                "/api/admin/config/reset",
                {"confirm": "Dropjak", "password": "root-jelszo-1"},
                cookie=cookie,
            )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            self.gw.settings.snapshot()["tunnels"],
            settings_store.default_tunnels(),
        )
        self.assertEqual(fake.removed, 1)
        self.assertEqual(len(self.restart_calls), 1)

    # -- service rules --------------------------------------------------------

    def _service_rule(self, cookie: str, rule_id: str = "mc-rule",
                      refs=None, **over) -> dict:
        payload = {
            "action": "create", "id": rule_id, "label": "MC szabály",
            "service_refs": refs if refs is not None else ["home/mc"],
            "default_ttl": 60, "max_ttl": 600,
        }
        payload.update(over)
        status, _, body = self.admin_post(
            "/api/admin/rules", payload, cookie=cookie
        )
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def test_service_rule_api_payload_and_crud(self) -> None:
        self.seed([agent(services=[service()])])
        cookie = self.admin_cookie()
        state = self._service_rule(cookie)
        rule = next(
            item for item in state["rules"] if item["id"] == "mc-rule"
        )
        self.assertEqual(rule["service_refs"], ["home/mc"])
        self.assertNotIn("domains", rule)
        self.assertNotIn("members", rule)
        self.assertEqual(rule["tcp"], [25565])
        self.assertEqual(rule["udp"], [])
        self.assertEqual(rule["direction"], "forward")
        self.assertEqual(
            rule["services"], [{
                "ref": "home/mc", "label": "Minecraft",
                "tcp": [25565], "udp": [], "domain": None,
            }],
        )
        self.assertEqual(
            rule["ports_label"], "Service: Minecraft (TCP 25565)"
        )

        # Update and duplicate: the references are kept.
        status, _, body = self.admin_post(
            "/api/admin/rules",
            {"action": "update", "id": "mc-rule", "label": "MC (új)",
             "service_refs": ["home/mc"], "default_ttl": 60,
             "max_ttl": 600},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        state = json.loads(body)
        rule = next(
            item for item in state["rules"] if item["id"] == "mc-rule"
        )
        self.assertEqual(rule["label"], "MC (új)")
        self.assertEqual(rule["service_refs"], ["home/mc"])

        status, _, body = self.admin_post(
            "/api/admin/rules",
            {"action": "duplicate", "id": "mc-rule",
             "new_id": "mc-copy"},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        copied = next(
            item for item in json.loads(body)["rules"]
            if item["id"] == "mc-copy"
        )
        self.assertEqual(copied["service_refs"], ["home/mc"])
        self.assertEqual(copied["tcp"], [25565])

        # The log contains the references.
        status, _, body = self.get(
            "/api/admin/logs?limit=200&event=admin_rule_updated",
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        rows = [
            row for row in json.loads(body)["logs"]
            if row.get("target") == "mc-rule"
        ]
        self.assertTrue(rows)
        self.assertEqual(rows[-1].get("service_refs"), "home/mc")

        for rule_id in ("mc-copy", "mc-rule"):
            status, _, body = self.admin_post(
                "/api/admin/rules", {"action": "delete", "id": rule_id},
                cookie=cookie,
            )
            self.assertEqual(status, 200, body)

    def test_domain_service_rule_api_grants_domain_through_proxy(self) -> None:
        """A domain-mode service can also be selected as a service rule."""
        self.prepare_domain([
            domain_service(
                service_id="web", domain="web.example.com",
                mappings=[mapping("tcp", "", "8080")],
            ),
        ])
        cookie = self.admin_cookie()
        self.gw.users.add("alice", "alice-jelszo-1")
        state = self._service_rule(
            cookie, "web-rule", refs=["home/web"],
            users=["alice"], groups=[],
        )
        rule_payload = next(
            item for item in state["rules"] if item["id"] == "web-rule"
        )
        self.assertEqual(rule_payload["service_refs"], ["home/web"])
        self.assertEqual(rule_payload["tcp"], [])
        self.assertEqual(rule_payload["udp"], [])
        self.assertEqual(rule_payload["services"], [{
            "ref": "home/web", "label": "Minecraft",
            "tcp": [], "udp": [], "domain": "web.example.com",
        }])
        self.assertEqual(
            rule_payload["ports_label"],
            "Service: Minecraft (web.example.com)",
        )
        # The static label shows the domain instead of the missing port.
        self.assertEqual(
            server.Handler._services_label(rule_payload["services"]),
            "Service: Minecraft (web.example.com)",
        )
        rule = self.gw.rules.get("web-rule")
        self.assertEqual(rule.grants, ())
        self.assertEqual(rule.service_domains, ("web.example.com",))

        session = self.gw.sessions.login("alice", "192.168.50.20")
        authorized = self.gw.sessions.authorize(
            session.token, "192.168.50.20", rule, 120
        )
        self.assertTrue(authorized.authorized)
        self.assertEqual(
            self.gw.sessions.domain_user(
                "192.168.50.20", "web.example.com"
            ),
            "alice",
        )
        self.assertIsNone(
            self.gw.sessions.domain_user(
                "192.168.50.20", "other.example.com"
            )
        )

        # Rename: the UI leaves the internal listening port unchanged, so
        # only the domain row changes. The signature and the resolved domain
        # are refreshed, the session is revoked, and the old snapshot
        # becomes invalid.
        stored = self.gw.settings.snapshot()["tunnels"]["agents"][0][
            "services"
        ][0]
        listen_port = stored["mappings"][0]["listen"]
        old_sig = settings_store.tunnel_service_index(
            self.gw.settings.snapshot()["tunnels"]
        )["home/web"]["signature"]
        self.assertIn(("domain", 0, "web.example.com", 0), old_sig)
        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_service_save", "agent_id": "home",
             "id": "web", "label": "Minecraft", "target_host": "web",
             "enabled": True, "domain": "web2.example.com",
             "mappings": [mapping("tcp", listen_port, "8080")]},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        payload = json.loads(body)
        self.assertEqual(payload.get("service_rules_refreshed"), "web-rule")
        self.assertGreaterEqual(int(payload.get("sessions_revoked", 0)), 1)
        new_sig = settings_store.tunnel_service_index(
            self.gw.settings.snapshot()["tunnels"]
        )["home/web"]["signature"]
        self.assertEqual(
            [row for row in old_sig if row[0] != "domain"],
            [row for row in new_sig if row[0] != "domain"],
        )
        self.assertIn(("domain", 0, "web2.example.com", 0), new_sig)
        current = self.gw.rules.get("web-rule")
        self.assertEqual(current.service_domains, ("web2.example.com",))
        self.assertFalse(self.gw._rule_available("alice", rule))
        self.assertIsNone(
            self.gw.sessions.validate(session.token, "192.168.50.20")
        )

    def test_domain_service_rename_keeps_listen_and_revokes_old_domain(
        self,
    ) -> None:
        """UI-like rename: the internal listen is unchanged, yet it revokes.

        The real interface sends back the existing internal listening port
        when editing the domain, so the port-based change detection would
        not notice. The domain must count as part of the effective mapping:
        the old session must not stay valid for the old domain, while the
        new login must work for the new domain.
        """
        self.prepare_domain([
            domain_service(
                service_id="web", domain="web.example.com",
                mappings=[mapping("tcp", "", "8080")],
            ),
        ])
        cookie = self.admin_cookie()
        self.gw.users.add("alice", "alice-jelszo-1")
        self._service_rule(
            cookie, "web-rule", refs=["home/web"],
            users=["alice"], groups=[],
        )
        stored = self.gw.settings.snapshot()["tunnels"]["agents"][0][
            "services"
        ][0]
        listen_port = stored["mappings"][0]["listen"]
        self.assertTrue(listen_port)
        old_sig = settings_store.tunnel_service_index(
            self.gw.settings.snapshot()["tunnels"]
        )["home/web"]["signature"]

        session = self.gw.sessions.login("alice", "192.168.50.20")
        rule = self.gw.rules.get("web-rule")
        self.assertTrue(self.gw.sessions.authorize(
            session.token, "192.168.50.20", rule, 120
        ).authorized)
        self.assertEqual(
            self.gw.sessions.domain_user(
                "192.168.50.20", "web.example.com"
            ),
            "alice",
        )

        # Exactly the UI payload: domain swap, listen and target unchanged.
        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_service_save", "agent_id": "home",
             "id": "web", "label": "Minecraft", "target_host": "web",
             "enabled": True, "domain": "web2.example.com",
             "mappings": [mapping("tcp", listen_port, "8080")]},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        payload = json.loads(body)
        self.assertEqual(payload.get("service_rules_refreshed"), "web-rule")
        self.assertGreaterEqual(int(payload.get("sessions_revoked", 0)), 1)
        self.assertIsNone(
            self.gw.sessions.domain_user(
                "192.168.50.20", "web.example.com"
            )
        )
        self.assertIsNone(
            self.gw.sessions.validate(session.token, "192.168.50.20")
        )
        new_sig = settings_store.tunnel_service_index(
            self.gw.settings.snapshot()["tunnels"]
        )["home/web"]["signature"]
        self.assertEqual(
            [row for row in old_sig if row[0] != "domain"],
            [row for row in new_sig if row[0] != "domain"],
        )
        self.assertIn(("domain", 0, "web2.example.com", 0), new_sig)

        # The new login with the fresh rule already opens the new domain.
        fresh = self.gw.sessions.login("alice", "192.168.50.20")
        current = self.gw.rules.get("web-rule")
        authorized = self.gw.sessions.authorize(
            fresh.token, "192.168.50.20", current, 120
        )
        self.assertTrue(authorized.authorized)
        self.assertEqual(
            self.gw.sessions.domain_user(
                "192.168.50.20", "web2.example.com"
            ),
            "alice",
        )
        self.assertIsNone(
            self.gw.sessions.domain_user(
                "192.168.50.20", "web.example.com"
            )
        )
        # The selection keeps the service reference for display.
        self.assertEqual(
            authorized.selections()[0].service_refs, ("home/web",)
        )

    def test_service_rule_api_rejects_unknown_disabled_and_mixed(self) -> None:
        self.seed([agent(services=[service()])])
        cookie = self.admin_cookie()

        status, _, body = self.admin_post(
            "/api/admin/rules",
            {"action": "create", "id": "bad-ref", "label": "Bad",
             "service_refs": ["home/nincs"]},
            cookie=cookie,
        )
        self.assertEqual(status, 400, body)
        self.assertIn("home/nincs", json.loads(body)["error"])
        self.assertIsNone(self.gw.rules.get("bad-ref"))

        status, _, body = self.admin_post(
            "/api/admin/rules",
            {"action": "create", "id": "mixed", "label": "Mixed",
             "service_refs": ["home/mc"], "tcp": [80]},
            cookie=cookie,
        )
        self.assertEqual(status, 400, body)
        self.assertIsNone(self.gw.rules.get("mixed"))

        # A rule cannot be created for a disabled service.
        self.seed([agent(services=[service(enabled=False)])])
        status, _, body = self.admin_post(
            "/api/admin/rules",
            {"action": "create", "id": "off-ref", "label": "Off",
             "service_refs": ["home/mc"]},
            cookie=cookie,
        )
        self.assertEqual(status, 400, body)
        self.assertIn("home/mc", json.loads(body)["error"])
        self.assertIsNone(self.gw.rules.get("off-ref"))

    def test_rule_assignment_users_and_groups_apply_and_replace(self) -> None:
        self.seed([agent(services=[service()])])
        cookie = self.admin_cookie()
        self.gw.users.add("alice", "alice-jelszo-1")
        self.gw.users.add("bob", "bob-jelszo-1")
        self.gw.groups.create("staff", {
            "label": "Staff", "rules": [], "members": ["alice"],
        })
        self.gw.rules.create("manual", {"label": "Manual", "tcp": [80]})
        self.gw.users.set_metadata("alice", rules=("manual",))

        # Creation with direct user and group assignment.
        self._service_rule(
            cookie, "svc-rule", users=["alice"], groups=["staff"]
        )
        self.assertIn(
            "svc-rule", self.gw.users.record("alice").rules
        )
        self.assertIn(
            "manual", self.gw.users.record("alice").rules
        )
        self.assertIn("svc-rule", self.gw.groups.get("staff").rules)
        self.assertNotIn("svc-rule", self.gw.users.record("bob").rules)

        # Update: exactly the submitted lists take effect.
        status, _, body = self.admin_post(
            "/api/admin/rules",
            {"action": "update", "id": "svc-rule", "label": "MC",
             "service_refs": ["home/mc"], "users": ["bob"], "groups": []},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        self.assertNotIn("svc-rule", self.gw.users.record("alice").rules)
        self.assertIn("manual", self.gw.users.record("alice").rules)
        self.assertIn("svc-rule", self.gw.users.record("bob").rules)
        self.assertNotIn("svc-rule", self.gw.groups.get("staff").rules)

        # Assignment through a group: it appears among the member's effective
        # rules, while the group's other rules are untouched.
        self._service_rule(
            cookie, "grp-rule", users=[], groups=["staff"]
        )
        self.assertIn("grp-rule", self.gw.groups.get("staff").rules)
        alice = self.gw.users.record("alice")
        effective = [
            rule.id for rule in self.gw.rules.effective_for(
                alice, self.gw.groups.groups_for("alice")
            )
        ]
        self.assertIn("grp-rule", effective)
        self.assertIn("manual", effective)
        self.assertNotIn("svc-rule", effective)

        # An omitted users/groups field does not change the assignments.
        status, _, body = self.admin_post(
            "/api/admin/rules",
            {"action": "update", "id": "grp-rule", "label": "Csoport",
             "service_refs": ["home/mc"]},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        self.assertIn("grp-rule", self.gw.groups.get("staff").rules)

        # Invalid user: the rule is not created.
        status, _, body = self.admin_post(
            "/api/admin/rules",
            {"action": "create", "id": "bad-user", "label": "Bad",
             "service_refs": ["home/mc"], "users": ["nobody"],
             "groups": []},
            cookie=cookie,
        )
        self.assertEqual(status, 400, body)
        self.assertIsNone(self.gw.rules.get("bad-user"))

        # The audit summarizes the added/removed users and groups in one
        # entry.
        status, _, body = self.get(
            "/api/admin/logs?limit=200&event=admin_rule_updated",
            cookie=cookie, source="127.0.0.5",
        )
        self.assertEqual(status, 200, body)
        row = next(
            item for item in json.loads(body)["logs"]
            if item.get("target") == "svc-rule"
        )
        self.assertEqual(row.get("users_added"), "bob")
        self.assertEqual(row.get("users_removed"), "alice")
        self.assertEqual(row.get("groups_removed"), "staff")

    def test_service_rule_lifecycle_guards(self) -> None:
        self.seed([agent(services=[service()])])
        cookie = self.admin_cookie()
        self.gw.users.add("alice", "alice-jelszo-1")
        self._service_rule(
            cookie, "mc-rule",
            users=["alice"], groups=[],
        )
        rule = self.gw.rules.get("mc-rule")
        self.assertEqual(rule.service_tcp, (25565,))
        session = self.gw.sessions.login("alice", "192.168.50.20")
        authorized = self.gw.sessions.authorize(
            session.token, "192.168.50.20", rule, 120
        )
        self.assertTrue(authorized.authorized)

        # Deletion remains forbidden while a rule references it.
        guard_payloads = (
            {"action": "tunnel_service_delete", "agent_id": "home",
             "id": "mc"},
            {"action": "tunnel_agent_delete", "id": "home"},
        )
        for payload in guard_payloads:
            with self.subTest(action=payload["action"]):
                status, _, body = self.admin_post(
                    "/api/admin/settings", payload, cookie=cookie
                )
                self.assertEqual(status, 400, body)
                error = json.loads(body)["error"]
                self.assertIn("rule references", error)
                self.assertIn("mc-rule", error)
                self.assertIn("MC szabály", error)
        # After the forbidden operations the agent and the service remain.
        stored = self.gw.settings.snapshot()["tunnels"]
        self.assertEqual(len(stored["agents"]), 1)
        self.assertTrue(stored["agents"][0]["enabled"])
        self.assertTrue(stored["agents"][0]["services"][0]["enabled"])

        # Disabling the referenced service is allowed (fail-closed):
        # the rule's access ceases and the session is torn down.
        service_payload = {
            "action": "tunnel_service_save", "agent_id": "home",
            "id": "mc", "label": "Minecraft", "target_host": "mc",
            "enabled": False,
            "mappings": [mapping("tcp", "25565", "25565")],
        }
        status, _, body = self.admin_post(
            "/api/admin/settings", service_payload, cookie=cookie
        )
        self.assertEqual(status, 200, body)
        payload = json.loads(body)
        self.assertIn("disabled", payload.get("message", ""))
        self.assertGreaterEqual(int(payload.get("sessions_revoked", 0)), 1)
        stored = self.gw.settings.snapshot()["tunnels"]
        self.assertFalse(stored["agents"][0]["services"][0]["enabled"])
        self.assertEqual(self.gw.rules.get("mc-rule").service_tcp, ())
        self.assertFalse(self.gw._rule_available("alice", rule))
        self.assertIsNone(
            self.gw.sessions.validate(session.token, "192.168.50.20")
        )

        # Re-enabling: the rule's resolved ports are restored.
        service_payload["enabled"] = True
        status, _, body = self.admin_post(
            "/api/admin/settings", service_payload, cookie=cookie
        )
        self.assertEqual(status, 200, body)
        stored = self.gw.settings.snapshot()["tunnels"]
        self.assertTrue(stored["agents"][0]["services"][0]["enabled"])
        self.assertEqual(self.gw.rules.get("mc-rule").service_tcp, (25565,))

        # Disabling the referenced agent is also allowed, and it tears down
        # the session of the referencing rule.
        current = self.gw.rules.get("mc-rule")
        session = self.gw.sessions.login("alice", "192.168.50.20")
        self.assertTrue(
            self.gw.sessions.authorize(
                session.token, "192.168.50.20", current, 120
            ).authorized
        )
        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_agent_update", "id": "home",
             "enabled": False},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        payload = json.loads(body)
        self.assertIn("disabled", payload.get("message", ""))
        self.assertIn("ceased", payload.get("message", ""))
        self.assertGreaterEqual(int(payload.get("sessions_revoked", 0)), 1)
        self.assertEqual(self.gw.rules.get("mc-rule").service_tcp, ())
        self.assertFalse(self.gw._rule_available("alice", current))
        self.assertIsNone(
            self.gw.sessions.validate(session.token, "192.168.50.20")
        )

        # After re-enabling, access can be resolved again.
        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_agent_update", "id": "home",
             "enabled": True},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        self.assertTrue(self.gw.settings.snapshot()["tunnels"]["agents"][0]["enabled"])
        self.assertEqual(self.gw.rules.get("mc-rule").service_tcp, (25565,))

        # Deletion with a reference still returns 400.
        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_agent_delete", "id": "home"},
            cookie=cookie,
        )
        self.assertEqual(status, 400, body)

        # After the referencing rule is deleted, the operations are allowed.
        status, _, body = self.admin_post(
            "/api/admin/rules", {"action": "delete", "id": "mc-rule"},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_service_save", "agent_id": "home",
             "id": "mc", "label": "Minecraft", "target_host": "mc",
             "enabled": False,
             "mappings": [mapping("tcp", "25565", "25565")]},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_agent_delete", "id": "home"},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)

    def test_service_mapping_change_reflects_and_revokes_sessions(self) -> None:
        self.seed([agent(services=[service()])])
        cookie = self.admin_cookie()
        self.gw.users.add("alice", "alice-jelszo-1")
        self._service_rule(
            cookie, "mc-rule", users=["alice"], groups=[]
        )
        rule = self.gw.rules.get("mc-rule")
        self.assertEqual(rule.service_tcp, (25565,))
        session = self.gw.sessions.login("alice", "192.168.50.20")
        authorized = self.gw.sessions.authorize(
            session.token, "192.168.50.20", rule, 120
        )
        self.assertTrue(authorized.authorized)
        self.assertIsNotNone(
            self.gw.sessions.validate(session.token, "192.168.50.20")
        )

        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_service_save", "agent_id": "home",
             "id": "mc", "label": "Minecraft", "target_host": "mc",
             "enabled": True,
             "mappings": [mapping("tcp", "25566", "25566")]},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        payload = json.loads(body)
        self.assertEqual(payload.get("service_rules_refreshed"), "mc-rule")
        self.assertGreaterEqual(int(payload.get("sessions_revoked", 0)), 1)
        # The rule's resolved port and the session were refreshed/torn down.
        self.assertEqual(self.gw.rules.get("mc-rule").service_tcp, (25566,))
        self.assertIsNone(
            self.gw.sessions.validate(session.token, "192.168.50.20")
        )

    def test_service_retarget_revokes_and_invalidates_old_grant(self) -> None:
        self.seed([agent(services=[service()])])
        cookie = self.admin_cookie()
        self.gw.users.add("alice", "alice-jelszo-1")
        self._service_rule(cookie, "mc-rule", users=["alice"], groups=[])
        old_rule = self.gw.rules.get("mc-rule")
        self.assertEqual(old_rule.service_tcp, (25565,))
        self.assertTrue(self.gw._rule_available("alice", old_rule))
        session = self.gw.sessions.login("alice", "192.168.50.20")
        authorized = self.gw.sessions.authorize(
            session.token, "192.168.50.20", old_rule, 120
        )
        self.assertTrue(authorized.authorized)

        # Only the target host changes; the listen port stays 25565.
        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_service_save", "agent_id": "home",
             "id": "mc", "label": "Minecraft", "target_host": "nas",
             "enabled": True,
             "mappings": [mapping("tcp", "25565", "25565")]},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        payload = json.loads(body)
        self.assertEqual(payload.get("service_rules_refreshed"), "mc-rule")
        self.assertGreaterEqual(int(payload.get("sessions_revoked", 0)), 1)
        self.assertEqual(self.gw.rules.get("mc-rule").service_tcp, (25565,))
        self.assertIsNone(
            self.gw.sessions.validate(session.token, "192.168.50.20")
        )
        # The old rule snapshot from before the target-host change is no longer
        # valid at decision time (the listen ports are identical, the signature differs).
        self.assertFalse(self.gw._rule_available("alice", old_rule))

        # Only the target port changes: the listen port remains 25565.
        current = self.gw.rules.get("mc-rule")
        session = self.gw.sessions.login("alice", "192.168.50.20")
        authorized = self.gw.sessions.authorize(
            session.token, "192.168.50.20", current, 120
        )
        self.assertTrue(authorized.authorized)
        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_service_save", "agent_id": "home",
             "id": "mc", "label": "Minecraft", "target_host": "nas",
             "enabled": True,
             "mappings": [mapping("tcp", "25565", "40000")]},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        payload = json.loads(body)
        self.assertEqual(payload.get("service_rules_refreshed"), "mc-rule")
        self.assertGreaterEqual(int(payload.get("sessions_revoked", 0)), 1)
        self.assertEqual(self.gw.rules.get("mc-rule").service_tcp, (25565,))
        self.assertIsNone(
            self.gw.sessions.validate(session.token, "192.168.50.20")
        )

    def test_service_retarget_revokes_collection_mediated_session(self) -> None:
        self.seed([agent(services=[service()])])
        cookie = self.admin_cookie()
        self.gw.users.add("alice", "alice-jelszo-1")
        self._service_rule(cookie, "mc-rule", users=[], groups=[])
        status, _, body = self.admin_post(
            "/api/admin/rules",
            {"action": "create", "id": "mc-col", "label": "MC gyűjtő",
             "collection": True, "members": ["mc-rule"],
             "users": ["alice"], "default_ttl": 60, "max_ttl": 600},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        collection = self.gw.rules.resolve_for(
            self.gw.users.record("alice"), [], "mc-col"
        )
        self.assertEqual(collection.service_refs, ("home/mc",))
        session = self.gw.sessions.login("alice", "192.168.50.20")
        authorized = self.gw.sessions.authorize(
            session.token, "192.168.50.20", collection, 120
        )
        self.assertTrue(authorized.authorized)

        status, _, body = self.admin_post(
            "/api/admin/settings",
            {"action": "tunnel_service_save", "agent_id": "home",
             "id": "mc", "label": "Minecraft", "target_host": "nas",
             "enabled": True,
             "mappings": [mapping("tcp", "25565", "25565")]},
            cookie=cookie,
        )
        self.assertEqual(status, 200, body)
        payload = json.loads(body)
        refreshed = (payload.get("service_rules_refreshed") or "").split(",")
        self.assertIn("mc-rule", refreshed)
        self.assertIn("mc-col", refreshed)
        self.assertGreaterEqual(int(payload.get("sessions_revoked", 0)), 1)
        self.assertIsNone(
            self.gw.sessions.validate(session.token, "192.168.50.20")
        )


if __name__ == "__main__":
    unittest.main()
