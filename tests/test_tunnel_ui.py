#!/usr/bin/env python3
"""Statikus és node-tesztek az admin Alagutak (WireGuard) fülhöz.

A teszt nem indít böngészőt: az ``index.html`` füljelölőit, az űrlapmezőket,
a POST-műveleteket, a letöltési URL-t és a HU/EN/DE szótárakat ellenőrzi.
A tiszta segédfüggvényeket (kézfogás kora, szolgáltatás-törzs, bájtformázás)
node-dal futtatjuk, mint a test_gateway.py QR-tesztje.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX_PATH = ROOT / "index.html"


def _js_function(name: str, source: str) -> str:
    match = re.search(
        rf"function {re.escape(name)}\([^)]*\) \{{.*?\n\}}", source, re.S
    )
    if match is None:
        raise AssertionError(f"hiányzó JS függvény: {name}")
    return match.group(0)


def _i18n_sections(source: str) -> tuple[str, str]:
    start = source.index("const I18N = {")
    patterns = source.index("const I18N_PATTERNS")
    i18n = source[start:patterns]
    en = i18n[i18n.index("en: {"):i18n.index("de: {")]
    de = i18n[i18n.index("de: {"):]
    return en, de


def _pattern_sections(source: str) -> tuple[str, str]:
    patterns = source[
        source.index("const I18N_PATTERNS"):source.index("function tr(text)")
    ]
    en = patterns[patterns.index("en: ["):patterns.index("de: [")]
    de = patterns[patterns.index("de: ["):]
    return en, de


class TunnelUiStaticTests(unittest.TestCase):
    """Az Alagutak fül statikus frontend-jelölői."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = INDEX_PATH.read_text(encoding="utf-8")

    def test_single_nav_button_and_render_dispatch(self) -> None:
        for token in (
            'data-admin="portproxy"',
            'data-i18n="Proxy és alagutak"',
            "function renderPortProxy()",
            "'Proxy és alagutak': 'portproxy'",
            "adminPanel.append(tunnelSettingsSection(tunnels));",
            "adminPanel.append(tunnelAgentsSection(agents));",
        ):
            self.assertIn(token, self.source, token)
        # A proxy és az alagutak egy fülön vannak.
        self.assertNotIn('data-admin="tunnels"', self.source)
        self.assertNotIn("adminTabName === 'tunnels'", self.source)
        self.assertNotIn("function renderTunnels()", self.source)
        # Az adminSetTab az alapértelmezett ágon a teljes állapotot tölti be,
        # így a fülnek nincs külön betöltője.
        start = self.source.index("function adminSetTab(name)")
        end = self.source.index("function openAdminEntity", start)
        self.assertIn("else return loadAdminState();", self.source[start:end])

    def test_settings_agents_and_services_wiring(self) -> None:
        for token in (
            "action: 'tunnel_settings'",
            "name: 'tunnel_port'",
            "name: 'tunnel_endpoint'",
            "action: 'tunnel_agent_add'",
            "action: 'tunnel_agent_update'",
            "action: 'tunnel_agent_delete'",
            "name: 'agent_label'",
            "action: 'tunnel_service_save'",
            "action: 'tunnel_service_delete'",
            "tunnelServicePayload(agent.id",
            "tunnelMappingError(mappings)",
            "tunnelMappingLabel(",
            "name: 'target_host'",
            "name: 'domain'",
            "name: 'domain_target'",
            "name: 'public'",
            "domain: domain.value",
            "domain_target: domainTarget.value",
            "public: publicWan.checked",
            "domain: service.domain || ''",
            "public: service.public === true",
            "mappingEditor.hidden = on",
            "domainTargetField.hidden = !on",
            "tunnelDomainTargetError(domainTarget.value)",
            "service.domain ? ` · ${tr('domain')}` : ''",
            "name: 'mapping_proto'",
            "name: 'mapping_listen'",
            "name: 'mapping_target'",
            "name: 'mappings_json'",
            "value: 'both'",
            "mappings: service.mappings || []",
            "/api/admin/tunnels/",
            "dropjak-agent-${id}.sh",
            "agent.bundle_url",
            "tunnels.error",
            # Elérhetőségi teszt: művelet, eredménytérkép, soron belüli
            # pirula és a hozzá tartozó fordítások.
            "action: 'tunnel_service_test'",
            "let tunnelTestResults = new Map();",
            "tunnelTestResults.get(tunnelTestKey(agent.id, service.id))",
            "tunnelClearTest(agent.id, service.id)",
            "tunnelClearAgentTests(agent.id)",
            "runTunnelServiceTest(agent, service)",
            "class: 'test-result '",
            "class: 'test-result-lines'",
            "tr(ok ? 'Elérhető' : 'Nem érhető el')",
            "tr('Teszt')",
            # Átdolgozott ügynök-/szolgáltatáslista.
            "class: 'tunnel-agent-card'",
            "class: 'tunnel-agent-head'",
            "class: 'tunnel-agent-address mono'",
            "class: 'tunnel-meta'",
            "class: 'tunnel-services'",
            "class: 'tunnel-service-row'",
            "tunnel-service-cell ${cls}",
            "class: 'tunnel-agent-new'",
            "class: 'tunnel-service-new'",
            "tunnelOpenAgentEdit(agent.id)",
            "tunnelOpenServiceEdit(agent.id, service.id)",
            # Állapotfrissítés és a letiltott ügynök semleges jelzése.
            "let tunnelStatusCheckedAt = null;",
            "let tunnelStatusLoading = false;",
            "function refreshTunnelStatus()",
            "/api/admin/tunnels/status",
            "adminState.tunnels = data.tunnels",
            "tunnelStatusCheckedAt = Number(data.checked_at)",
            "tunnelCheckedLabel(tunnelStatusCheckedAt)",
            "class: 'tunnel-status-bar'",
            "tunnelStatusPill(agent)",
            "tunnelActiveState(agent)",
            "tunnelLastSyncLabel(agent.last_sync)",
            "class: 'tunnel-status-spinner'",
        ):
            self.assertIn(token, self.source, token)
        # A törlések oldalon belüli, kétlépcsős megerősítést használnak:
        # a natív confirm() helyett a kártya/sor maga változik meg, mert a
        # böngésző letilthatja a felugró párbeszédablakokat.
        card = _js_function("tunnelAgentCard", self.source)
        services = _js_function("tunnelServicesSection", self.source)
        box = _js_function("tunnelDeleteConfirmBox", self.source)
        self.assertIn("class: 'delete-confirm'", box)
        self.assertIn("class: 'danger small'", box)
        self.assertIn("class: 'ghost small'", box)
        self.assertIn("tr('Törlés')", box)
        self.assertIn("tr('Mégse')", box)
        self.assertIn("tunnelDeleteConfirm = null;", box)
        self.assertIn("tunnelDeleteConfirm = null;", _js_function("adminSend", self.source))
        for section in (card, services):
            self.assertNotIn("confirm(", section)
            self.assertIn("tunnelDeleteConfirmBox(", section)
        # Az ügynök törlése a szolgáltatásait is törli; a figyelmeztetés
        # szövege változatlan, hogy a fordítói minták érvényesek maradjanak.
        self.assertIn(
            "tr(`Biztosan törlöd az ügynököt: ${agent.label}? "
            "A szolgáltatásai is törlődnek.`)",
            card,
        )
        self.assertIn(
            "tr(`Biztosan törlöd a szolgáltatást: ${service.label}?`)",
            services,
        )
        # Az első kattintás csak kijelöli a törlést; a payload a megerősítő
        # gombon marad, ugyanaz, mint korábban.
        self.assertIn("tunnelDeleteConfirm = { kind: 'agent', id: agent.id }", card)
        self.assertIn(
            "tunnelDeleteConfirm = { kind: 'service', id: service.id, "
            "agentId: agent.id }",
            services,
        )
        self.assertIn(
            "action: 'tunnel_agent_delete', id: agent.id", card,
        )
        self.assertIn(
            "action: 'tunnel_service_delete', agent_id: agent.id, id: service.id",
            services,
        )
        # A létrehozás után azonnal letöltődik a konfiguráció.
        self.assertIn("if (data.agent_id) await downloadTunnelConfig(", self.source)
        self.assertIn(
            "A fájl a WireGuard titkos kulcsot is tartalmazza",
            self.source,
        )

    def test_agent_panel_layout_and_one_form_at_a_time(self) -> None:
        # A CSS a meglévő tokenekre épül; a szűk nézetben a szolgáltatás-
        # sorok egymás alá kerülnek, nem görget oldalra.
        for token in (
            ".tunnel-agent-card{",
            ".tunnel-agent-head{",
            ".tunnel-meta{",
            ".tunnel-services{",
            ".tunnel-service-row{",
            ".test-result{",
            ".test-result.ok{",
            ".test-result.err{",
            "@media (max-width:760px){",
            ".tunnel-service-cell .cell-label{display:block}",
            ".tunnel-service-row{grid-template-columns:1fr",
        ):
            self.assertIn(token, self.source, token)
        # Az „Új ügynök” lenyitható; a szolgáltatás űrlapja is disclosure.
        agents = _js_function("tunnelAgentsSection", self.source)
        services = _js_function("tunnelServicesSection", self.source)
        self.assertIn("el('details', { class: 'tunnel-agent-new' }", agents)
        self.assertIn("el('summary', {}, tr('Új ügynök'))", agents)
        self.assertIn("el('details', { class: 'tunnel-service-new'", services)
        self.assertIn("tr('Új szolgáltatás')", services)
        # Egyszerre csak egy szerkesztő: ugyanaz az adminEdit állapot dönt,
        # és a másik ágban nem renderelődik űrlap.
        self.assertIn("adminEdit && adminEdit.kind === 'tunnel-service'", services)
        self.assertIn("&& adminEdit.agent === agent.id", services)
        self.assertIn("if (editingId === 'new')", services)
        self.assertIn("else if (editingService)", services)
        card = _js_function("tunnelAgentCard", self.source)
        self.assertIn("adminEdit.kind === 'tunnel-agent'", card)
        self.assertIn("tunnelOpenAgentEdit(agent.id)", card)
        # A teszt gomb a sorban van, és töltés közben letiltott.
        self.assertIn("disabled: testing", services)
        self.assertIn("action: 'tunnel_service_test'", self.source)
        self.assertIn("agent_id: agent.id,", self.source)
        self.assertIn("service_id: service.id", self.source)
        # Nincs natív alert()/confirm() az alagút-szakaszban.
        start = self.source.index(
            "/* ============================================================ admin: alagutak */"
        )
        end = self.source.index(
            "/* ============================================================ admin: munkamenetek */",
            start,
        )
        section = self.source[start:end]
        self.assertNotIn("alert(", section)
        self.assertNotIn("confirm(", section)

    def test_agent_status_refresh_and_inline_error(self) -> None:
        # Az állapotfrissítés gomb akkor is látszik, ha nincs ügynök; a
        # kattintás GET-et indít, és a válaszból csak az alagút-nézet
        # cserélődik. Hiba esetén a flash az ügynöklista tetején is
        # megjelenik, nem csak az oldal tetején.
        agents = _js_function("tunnelAgentsSection", self.source)
        self.assertIn(
            "if (adminFlash && adminFlash.kind === 'err')", agents
        )
        self.assertIn("class: 'admin-flash err'", agents)
        self.assertIn("onclick: refreshTunnelStatus", agents)
        self.assertIn("disabled: tunnelStatusLoading", agents)
        self.assertIn("tunnelCheckedLabel(tunnelStatusCheckedAt)", agents)
        self.assertIn("tunnelStatusPill(agent)", self.source)
        refresh = _js_function("refreshTunnelStatus", self.source)
        self.assertIn("fetch('/api/admin/tunnels/status'", refresh)
        self.assertIn("cache: 'no-store'", refresh)
        self.assertIn("adminState.tunnels = data.tunnels", refresh)
        self.assertNotIn("postJson(", refresh)

        # Az „aktív” csak engedélyezett, friss kézfogású és legfeljebb
        # 90 másodperce szinkronizált ügynöknél jelenik meg; letiltva
        # semleges pirula, nem offline.
        active = _js_function("tunnelActiveState", self.source)
        self.assertIn("agent.enabled === false", active)
        self.assertIn("< 180", active)
        self.assertIn("<= 90", active)
        self.assertIn("return 'active'", active)
        pill = _js_function("tunnelStatusPill", self.source)
        self.assertIn("' neutral'", pill)
        self.assertIn("disabled: 'letiltva'", pill)
        meta = _js_function("tunnelAgentCard", self.source)
        self.assertIn("tunnelLastSyncLabel(agent.last_sync)", meta)

    def test_proxy_and_tunnels_share_one_page(self) -> None:
        start = self.source.index("function renderPortProxy()")
        end = self.source.index("admin: munkamenetek", start)
        body = self.source[start:end]
        # A közvetlen proxy űrlapja és az alagút-szakasz ugyanabban a
        # renderelésben van; a közvetlen proxyhoz nem kell ügynök.
        self.assertIn("action: 'port_proxies'", body)
        self.assertIn("'Közvetlen proxyk'", body)
        self.assertIn("tunnelSettingsSection(tunnels)", body)
        self.assertIn("tunnelAgentsSection(agents)", body)

    def test_service_rule_kind_and_direct_assignment_wiring(self) -> None:
        # A szolgáltatás szabály saját típus, a hozzárendelés pedig minden
        # szabálytípusnál a közvetlen felhasználó/csoport halmazt küldi.
        for token in (
            "['service', 'Szolgáltatás']",
            "if ((rule.service_refs || []).length) return 'service';",
            "'service_refs'",
            "'rule_users'",
            "'rule_groups'",
            "service_refs: serviceRefs",
            "serviceBox.disabled = collection || domain;",
            "collectionBox.disabled = domain || service;",
            "users: directUsers",
            "groups: directGroups",
        ):
            self.assertIn(token, self.source, token)
        # A gyűjtő tagválasztója nem zárja ki a szolgáltatás szabályokat.
        start = self.source.index("const memberChoices")
        end = self.source.index("const submit", start)
        choices = self.source[start:end]
        self.assertNotIn("service", choices)
        self.assertIn("!item.collection", choices)

    def test_rule_service_picker_includes_domain_services(self) -> None:
        """A domain-módú szolgáltatás szolgáltatás-szabályként is választható."""
        self.assertNotIn("if (service.domain) continue;", self.source)
        start = self.source.index("const serviceChoices")
        end = self.source.index("const savedDirection", start)
        picker = self.source[start:end]
        self.assertIn("for (const service of agent.services || [])", picker)
        self.assertIn(
            "service.domain ? ` · ${tr('domain')}` : ''", picker
        )
        # A jelölés mindhárom nyelven fordul.
        en, de = _i18n_sections(self.source)
        self.assertIn("'domain': 'domain'", en)
        self.assertIn("'domain': 'Domain'", de)
        # A súgó kimondja, hogy a domain a portál proxyján át nyílik.
        self.assertIn(
            "a domain-módú szolgáltatás a portál proxyján keresztül "
            "a domainjét adja", self.source,
        )
        # A szabálysor a domaint a szolgáltatás neve mellett mutatja.
        summary = _js_function("ruleSummary", self.source)
        self.assertIn(
            "service.domain ? ` (${service.domain})` : ''", summary
        )

    def test_domains_tab_lists_tunnel_domains_with_challenge(self) -> None:
        for token in (
            "const tunnelDomains = [];",
            "if (service.domain) tunnelDomains.push({ agent, service });",
            "tr('Alagút-domainek')",
            "challenge: challenge.read()",
            "tr('Challenge mentése')",
            "'Alagút-domainek': 'Tunnel domains'",
            # A domain szabály választója az alagút-domaineket is kínálja.
            "[...(settingsData().proxy_routes || []), ...tunnelDomains]",
            "root: service.domain, tunnel: true",
            "'Alagút': 'Tunnel'",
        ):
            self.assertIn(token, self.source, token)
        # Az új szolgáltatás űrlapján nincs külön aktív pipa: az állapotot
        # a szolgáltatás sorának kapcsolója kezeli.
        start = self.source.index(
            "function tunnelServiceForm(agent, service)"
        )
        end = self.source.index("function tunnelServicesSection", start)
        self.assertNotIn("name: 'enabled'", self.source[start:end])

    def test_tunnel_strings_are_translated(self) -> None:
        en, de = _i18n_sections(self.source)
        sources = (
            "Proxy és alagutak",
            "Közvetlen port proxyk ügynök nélkül, és WireGuard-alapú "
            "alagút ügynökök a saját hálózathoz.",
            "Közvetlen proxyk",
            "A közvetlen proxy a felhő szerveréről továbbít, ügynök nélkül. "
            "Alagút csak akkor kell, ha a szolgáltatás a saját hálózatodban "
            "fut.",
            "Alagutak",
            "WireGuard-alapú alagút ügynökök és a rajtuk át elérhető "
            "szolgáltatások.",
            "A WireGuard-kezelő hibája:",
            "Alagút-beállítások",
            "WireGuard port",
            "Nyilvános végpont",
            "Az ügynök konfigurációjában használt cím:",
            "Ügynökök",
            "Új ügynök",
            "Ügynök neve",
            "Utolsó kézfogás",
            "Forgalom",
            "soha",
            "online",
            "offline",
            "Telepítő letöltése",
            "Még nincs ügynök. Az „Új ügynök” gombbal hozhatsz létre egyet.",
            "Szolgáltatások",
            "Ehhez az ügynökhöz még nincs szolgáltatás.",
            "Cél host",
            "pl. mc vagy 192.168.1.20",
            "Port-hozzárendelések",
            "Külső port",
            "Belső port",
            "Hozzárendelés eltávolítása",
            "+ Port hozzáadása",
            "Az alagút portja a külső porttal azonos.",
            "Adj meg legalább egy port-hozzárendelést.",
            "A külső port nem lehet üres.",
            "A belső port nem lehet üres.",
            "A külső és a belső portok száma egyezzen meg.",
            "Új szolgáltatás",
            "Szolgáltatás szerkesztése",
            "mindkettő",
            # Domaines (Caddy mögötti) szolgáltatás.
            "Domain (opcionális)",
            "Ha kitöltöd, a szolgáltatás a proxy gyökérdomain alatt, "
            "HTTPS-en érhető el.",
            "Célport",
            "publikus",
            "Publikus: portál-belépés nélkül elérhető.",
            "Publikus: domain szabály nélkül elérhető; privát módban domain "
            "szabály kell.",
            "A domaines szolgáltatást a Caddy szolgálja ki HTTPS-en; a belső "
            "alagút-portot a rendszer automatikusan osztja ki. Publikus: "
            "portál- és domain szabály nélkül elérhető. Privát: domain "
            "szabály szükséges.",
            "A domaines szolgáltatáshoz egyetlen célport kell.",
            # Szolgáltatás szabály és közvetlen hozzárendelés.
            "Szolgáltatás (alagút)",
            "Közvetlen hozzárendelés",
            "Keresés a szolgáltatások között…",
            "A szolgáltatás szabály a kiválasztott alagút-szolgáltatásokat "
            "nyitja meg; a domain-módú szolgáltatás a portál proxyján "
            "keresztül a domainjét adja, tűzfalport nélkül. Az irány és a "
            "portok nem értelmezettek.",
            "A letiltott szolgáltatás nem választható; előbb engedélyezd az "
            "Alagutak fülön.",
            "Legalább egy szolgáltatást válassz a szolgáltatás szabályhoz.",
            "A csoporttagságot a csoport szerkesztőjében állítod be; itt csak "
            "a szabály közvetlen hozzárendelését adod meg.",
            "Az ügynök létrehozása nem sikerült.",
            "A konfiguráció letöltődött. A fájl a WireGuard titkos kulcsot "
            "is tartalmazza: őrizd bizalmasan.",
            "A konfiguráció letöltése nem sikerült.",
            # A szerver által visszaadott sikerüzenetek is fordulnak.
            "Az alagút beállításai mentve.",
            "Az ügynök létrejött; töltsd le a konfigurációját.",
            "Az ügynök mentve.",
            "Az ügynök törölve.",
            "A szolgáltatás mentve.",
            "A szolgáltatás törölve.",
            # Elérhetőségi teszt és az új oszlop-/állapotcímkék.
            "Elérés",
            "Teszt",
            "Teszt folyamatban…",
            "Elérhető",
            "Nem érhető el",
            "A teszt nem sikerült.",
            "Domain",
            "csatlakozás létrejött",
            "időtúllépés",
            "elutasítva",
            "elutasítva (ICMP)",
            "kiküldve, UDP-válasz nem várható",
            "válasz érkezett",
            "tunnel: az ügynök ki van kapcsolva",
            "tunnel: a szolgáltatás ki van kapcsolva",
            "tunnel: nincs tesztelhető portleképezés",
            "tunnel: az ügynök- és szolgáltatás-azonosító kell",
            # Állapotfrissítés, utolsó szinkron és a letiltás üzenetei.
            "utolsó szinkron",
            "nincs szinkron",
            "Állapot frissítése",
            "Frissítés…",
            "Ellenőrizve:",
            "Az állapot frissítése nem sikerült.",
            "Az ügynök letiltva.",
            "Az ügynök letiltva; a hivatkozó szabályok hozzáférése "
            "megszűnt.",
            "A szolgáltatás letiltva.",
            "A szolgáltatás letiltva; a hivatkozó szabályok hozzáférése "
            "megszűnt.",
        )
        for text in sources:
            with self.subTest(text=text):
                self.assertIn(f"'{text}':", en, f"hiányzó angol fordítás: {text}")
                self.assertIn(f"'{text}':", de, f"hiányzó német fordítás: {text}")

    def test_confirmation_patterns_and_audit_label(self) -> None:
        en, de = _pattern_sections(self.source)
        for section in (en, de):
            self.assertIn("Biztosan törlöd az ügynököt:", section)
            self.assertIn("Biztosan törlöd a szolgáltatást:", section)
        # A figyelmeztetések oldalon belüli, kétlépcsős megerősítésben
        # jelennek meg; a natív confirm() már nem használt itt.
        for section in (
            _js_function("tunnelAgentCard", self.source),
            _js_function("tunnelServicesSection", self.source),
        ):
            self.assertNotIn("confirm(", section)
            self.assertIn("tunnelDeleteConfirmBox(", section)
        self.assertIn("Delete agent ${m[1]}?", en)
        self.assertIn("Delete service ${m[1]}?", en)
        self.assertIn("Agent ${m[1]} wirklich löschen?", de)
        self.assertIn("Dienst ${m[1]} wirklich löschen?", de)
        # A szerveroldali alagút-validációs hibák mintái is fordítottak.
        for section in (en, de):
            self.assertIn("tunnel: a WireGuard port 1024 és 65535 között lehet", section)
            self.assertIn("tunnel: a végpont szöveg kell", section)
            self.assertIn("tunnel: a hallgató port már foglalt:", section)
            self.assertIn("tunnel: a szolgáltatás domainje csak proxy "
                          "gyökérdomain alatt lehet", section)
            self.assertIn("tunnel: domain szabály hivatkozik rá", section)
            self.assertIn("tunnel: nincs szabad belső alagút-port", section)
            self.assertIn("a public mező igaz", section)
            self.assertIn("tunnel: a protokoll tcp, udp vagy both lehet", section)
            self.assertIn("hálózati hiba: ", section)
            # Új többportos/szolgáltatás-validációs üzenetek és a dinamikus
            # „Szolgáltatás: …” ports_label fordítása.
            self.assertIn("tunnel: a mappings lista kell", section)
            self.assertIn("tunnel: a célportok száma nem egyezik", section)
            self.assertIn("tunnel: ugyanaz a hallgató port eltérő célportra mutat", section)
            self.assertIn("Szolgáltatás: (.*)", section)
        self.assertIn(
            "admin_tunnel_changed: ['Alagút módosítva', 'Tunnel changed', "
            "'Tunnel geändert']",
            self.source,
        )


class TunnelHelpersNodeTests(unittest.TestCase):
    """A tiszta segédfüggvények valódi node-futtatással."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = INDEX_PATH.read_text(encoding="utf-8")

    @unittest.skipUnless(shutil.which("node"), "node nem érhető el")
    def test_helpers(self) -> None:
        age = _js_function("tunnelHandshakeAge", self.source)
        payload = _js_function("tunnelServicePayload", self.source)
        size = _js_function("formatBytes", self.source)
        parse_ports = _js_function("parsePortInput", self.source)
        format_ports = _js_function("formatPortRanges", self.source)
        mapping_error = _js_function("tunnelMappingError", self.source)
        domain_error = _js_function("tunnelDomainTargetError", self.source)
        mapping_label = _js_function("tunnelMappingLabel", self.source)
        parse_sequence = _js_function("parsePortSequence", self.source)
        format_sequence = _js_function("formatPortSequence", self.source)
        rule_kind = _js_function("ruleKind", self.source)
        rule_summary = _js_function("ruleSummary", self.source)
        script = (
            "const assert = require('assert');\n"
            "const tr = text => String(text);\n"
            + age + "\n"
            + payload + "\n"
            + size + "\n"
            + parse_ports + "\n"
            + parse_sequence + "\n"
            + format_sequence + "\n"
            + format_ports + "\n"
            + mapping_error + "\n"
            + domain_error + "\n"
            + mapping_label + "\n"
            + rule_kind + "\n"
            # Minimális DOM a ruleSummary összegzésének vizsgálatához.
            + r"""
class FakeNode {
  constructor(tag) {
    this.tagName = tag; this.children = [];
    this.textContent = ''; this.className = ''; this.attrs = {};
  }
  setAttribute(key, value) { this.attrs[key] = value; }
  addEventListener() {}
  append(...nodes) {
    for (const node of nodes.flat()) {
      if (node === null || node === undefined || node === false) continue;
      this.children.push(node);
    }
  }
}
function el(tag, attrs = {}, ...children) {
  const node = new FakeNode(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = String(value);
    else node.setAttribute(key, value);
  }
  node.append(...children);
  return node;
}
function entityLink(text) {
  const node = new FakeNode('a');
  node.textContent = String(text);
  return node;
}
const ruleDisplayLabel = label => String(label ?? '');
const textOf = node => node.textContent
  || (node.children || []).map(textOf).join(' ');
""" + rule_summary + "\n"
            + r"""
assert.strictEqual(tunnelHandshakeAge(null), null);
assert.strictEqual(tunnelHandshakeAge(0), null);
assert.strictEqual(tunnelHandshakeAge('invalid', 1000), null);
assert.deepStrictEqual(
  tunnelHandshakeAge(995, 1000), { value: 5, unit: 'second' });
assert.deepStrictEqual(
  tunnelHandshakeAge(940, 1000), { value: 1, unit: 'minute' });
assert.deepStrictEqual(
  tunnelHandshakeAge(400, 1000), { value: 10, unit: 'minute' });
assert.deepStrictEqual(
  tunnelHandshakeAge(-2600, 1000), { value: 1, unit: 'hour' });
assert.deepStrictEqual(
  tunnelHandshakeAge(1000 - 86400 * 2, 1000), { value: 2, unit: 'day' });
// Jövőbeli időpont nem ad negatív kort.
assert.deepStrictEqual(
  tunnelHandshakeAge(1100, 1000), { value: 0, unit: 'second' });

assert.deepStrictEqual(
  tunnelServicePayload('a1', {
    label: '  MC  ', target_host: ' mc ', enabled: false,
    mappings: [
      { proto: 'udp', listen: ' 25565 ', target: ' 25565 ' },
      { proto: 'icmp', listen: '8000-8001', target: '9000-9001' }
    ]
  }),
  {
    action: 'tunnel_service_save', agent_id: 'a1', label: 'MC',
    target_host: 'mc', enabled: false, public: false, domain: '',
    mappings: [
      { proto: 'udp', listen: '25565', target: '25565' },
      { proto: 'tcp', listen: '8000-8001', target: '9000-9001' }
    ]
  });
// Ismeretlen protokoll TCP-re esik vissza; id nélkül nincs id mező.
assert.deepStrictEqual(
  tunnelServicePayload('a1', {
    id: 's1', label: 'web', target_host: 'h', mappings: []
  }),
  {
    action: 'tunnel_service_save', agent_id: 'a1', id: 's1',
    label: 'web', target_host: 'h', enabled: true, public: false,
    domain: '', mappings: []
  });
// Domaines mód: egyetlen TCP-leképezés, a meglévő belső port megtartásával.
assert.deepStrictEqual(
  tunnelServicePayload('a1', {
    id: 's2', label: 'web', target_host: 'h', public: true,
    domain: ' mc.example.com ',
    mappings: [{ proto: 'udp', listen: '41001', target: '9999' }],
    domain_target: ' 8443 '
  }),
  {
    action: 'tunnel_service_save', agent_id: 'a1', id: 's2',
    label: 'web', target_host: 'h', enabled: true, public: true,
    domain: 'mc.example.com',
    mappings: [{ proto: 'tcp', listen: '41001', target: '8443' }]
  });
// A sor kapcsolója nem küld domain_target mezőt: a meglévő célport marad,
// nem ürül ki (korábban ez „legalább egy port kell” hibát adott).
assert.deepStrictEqual(
  tunnelServicePayload('a1', {
    id: 's3', label: 'mptech', target_host: 'cave-horror', enabled: false,
    domain: 'mptech.example.com',
    mappings: [{ proto: 'tcp', listen: '41001', target: '8080' }]
  }),
  {
    action: 'tunnel_service_save', agent_id: 'a1', id: 's3',
    label: 'mptech', target_host: 'cave-horror', enabled: false,
    public: false, domain: 'mptech.example.com',
    mappings: [{ proto: 'tcp', listen: '41001', target: '8080' }]
  });
assert.ok(!('id' in tunnelServicePayload('a1', {
  label: 'x', target_host: 'h',
  mappings: [{ proto: 'tcp', listen: '1', target: '1' }]
})));
// Régi mezők nem kerülhetnek a törzsbe.
const legacyPayload = tunnelServicePayload('a1', {
  label: 'x', listen_port: 1, target: 'h:1', proto: 'tcp',
  mappings: [{ proto: 'tcp', listen: '1', target: '1' }]
});
assert.ok(!('listen_port' in legacyPayload));
assert.ok(!('target' in legacyPayload));
assert.ok(!('tunnel_port' in legacyPayload));

// Port-hozzárendelés ellenőrzése: üres lista, hiányzó oldal, eltérő hossz.
assert.strictEqual(
  tunnelMappingError([]), 'Adj meg legalább egy port-hozzárendelést.');
assert.strictEqual(
  tunnelMappingError([{ listen: '8000-8100', target: '18000-18100' }]), '');
assert.strictEqual(
  tunnelMappingError([{ listen: '80,443', target: '8080,8443' }]), '');
assert.strictEqual(
  tunnelMappingError([
    { listen: '25565', target: '25565' },
    { listen: '19132', target: '19132' }
  ]), '');
assert.match(
  tunnelMappingError([{ listen: '8000-8100', target: '18000' }]),
  /A külső és a belső portok száma egyezzen meg\./);
assert.match(
  tunnelMappingError([{ listen: '', target: '18000' }]),
  /A külső port nem lehet üres\./);
assert.match(
  tunnelMappingError([{ listen: '80', target: '' }]),
  /A belső port nem lehet üres\./);
assert.match(
  tunnelMappingError([{ listen: 'abc', target: '1' }]),
  /Külső port: érvénytelen port: abc/);
// A szerver a beírt sorrendben, indexenként párosít: az ismétlődő célport
// nem olvad össze a darabszám-ellenőrzés előtt, a rendezés pedig nem
// cseréli fel a párokat.
assert.strictEqual(
  tunnelMappingError([{ listen: '8000,8001', target: '9001,9001' }]), '');
assert.strictEqual(
  tunnelMappingError([{ listen: '8000,8001', target: '9001,9000' }]), '');
assert.deepStrictEqual(
  parsePortSequence('8000,8001,9000-9001'),
  { ports: [8000, 8001, 9000, 9001] });
assert.deepStrictEqual(
  parsePortSequence('8000,8000'),
  { ports: [8000, 8000] });
// Domaines mód: egyetlen célport, a belső portot a szerver osztja ki.
assert.strictEqual(tunnelDomainTargetError('25565'), '');
assert.strictEqual(
  tunnelDomainTargetError('8000-8001'),
  'A domaines szolgáltatáshoz egyetlen célport kell.');
assert.strictEqual(
  tunnelDomainTargetError(''),
  'A domaines szolgáltatáshoz egyetlen célport kell.');
assert.match(tunnelDomainTargetError('abc'), /Célport: érvénytelen port: abc/);

// A tömör megjelenítés a hallgató és a belső tartományt is mutatja.
assert.strictEqual(
  tunnelMappingLabel({ proto: 'tcp', listen: '8000-8100', target: '18000-18100' }),
  'TCP 8000–8100 → 18000–18100');
assert.strictEqual(
  tunnelMappingLabel({ proto: 'both', listen: '80', target: '8080' }),
  'TCP+UDP 80 → 8080');
// A céloldal is a párosítási sorrendben jelenik meg, nem rendezve.
assert.strictEqual(
  tunnelMappingLabel({ proto: 'tcp', listen: '8000,8001', target: '9001,9000' }),
  'TCP 8000–8001 → 9001, 9000');

// A szolgáltatás szabály felismerése az irány előtt történik.
assert.strictEqual(ruleKind({ service_refs: ['a1/s1'] }), 'service');
assert.strictEqual(
  ruleKind({ service_refs: ['a1/s1'], direction: 'input' }), 'service');
assert.strictEqual(ruleKind({ direction: 'input' }), 'input');
assert.strictEqual(ruleKind({ domains: ['example.com'] }), 'domain');
assert.strictEqual(ruleKind({ collection: true }), 'collection');
// A gyűjtő elsőbbsége: a tagokból összesített service_refs/services nem
// teszi szolgáltatás-szabállyá a gyűjtőt.
assert.strictEqual(ruleKind({
  collection: true, members: ['svc'],
  service_refs: ['a1/s1'], services: [{ ref: 'a1/s1', label: 'MC' }]
}), 'collection');
assert.strictEqual(ruleKind({
  members: ['svc'], service_refs: ['a1/s1']
}), 'collection');
assert.strictEqual(ruleKind({
  domains: ['example.com'], service_refs: ['a1/s1']
}), 'domain');
// A gyűjtő összegzése a tagok nevét mutatja, nem szolgáltatás-chipet.
const collectionSummary = ruleSummary({
  id: 'col', label: 'Gyűjtő', collection: true, members: ['svc'],
  service_refs: ['a1/s1'], services: [{ ref: 'a1/s1', label: 'MC' }],
  ports_label: 'TCP 25565'
}, new Map([['svc', { id: 'svc', label: 'Szerver szabály' }]]));
const collectionText = (collectionSummary.children || []).map(textOf).join(' ');
assert.ok(collectionText.includes('Szerver szabály'));
assert.ok(!collectionText.includes('Szolgáltatás'));

assert.strictEqual(formatBytes(0), '0 B');
assert.strictEqual(formatBytes(1024), '1.0 KB');
assert.strictEqual(formatBytes(1536), '1.5 KB');
assert.strictEqual(formatBytes(1048576), '1.0 MB');
assert.strictEqual(formatBytes(-5), '0 B');
process.stdout.write(JSON.stringify({ ok: true }));
"""
        )
        with tempfile.TemporaryDirectory(prefix="hv-tunnel-") as tmp:
            script_path = Path(tmp) / "helpers.js"
            script_path.write_text(script, encoding="utf-8")
            check = subprocess.run(
                [shutil.which("node"), "--check", str(script_path)],
                cwd=tmp, capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(check.returncode, 0, check.stderr)
            result = subprocess.run(
                [shutil.which("node"), str(script_path)],
                cwd=tmp, capture_output=True, text=True, timeout=60,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"ok": True})


if __name__ == "__main__":
    unittest.main()
