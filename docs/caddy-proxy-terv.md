# Caddy-jellegű reverse proxy és automatikus TLS integrációja a Dropjakba

**Dátum:** 2026-10-20

**Státusz: implementálva (3.4.0), a tervtől eltérően:** statikus `deploy/Caddyfile` admin API és újratöltés nélkül; az útvonalak portálkapuzottak (`/api/proxy/ask`, `/api/proxy/auth` forward_auth). Lásd a README „Subdomain proxy (Caddy)” részét. Az alábbi szöveg az eredeti terv.

Ez a dokumentum kizárólag tervet tartalmaz. A javaslat nem került implementálásra, a repóban a `docs/caddy-proxy-terv.md` létrehozásán kívül nem történt változtatás, nem történt commit, telepítés vagy host firewall módosítás.

---

## 1. Vezetői összefoglaló

A felvetés: egy domain vagy subdomain forwardolása egy portra, automatikus SSL-lel, Caddy-szerűen. A Dropjak jelenleg captive-portal alapú, fail-closed nftables tűzfallal védett hálózati átjáró, amely Docker `network_mode: host` módban fut, és a host `inet hatarvedelem` nftables tábláját programozza. A cél egy olyan bővítés, amely publikus HTTP(S) szolgáltatásokat tesz elérhetővé domain néven, automatikus tanúsítvánnyal, anélkül hogy a meglévő hozzáférés-vezérlési invariánsok sérülnének.

**Javasolt architektúra:**

- külön, host network módben futó **Caddy konténer**, a Dropjak portál konténerétől független életciklussal;
- a portál a **Caddy admin API-n** (`POST 127.0.0.1:2019/load`, `Content-Type: text/caddyfile`) keresztül alkalmazza a generált konfigurációt;
- a domain → port leképezéseket a portál új `proxy-settings.json` state fájlja tárolja, és az admin UI egy új **Proxy** fülön kezeli;
- a WAN 80/443-at **nem DNAT-oljuk**, mert a host-local Caddy az `input` hookon kapja a forgalmat; egy új, alapból üres `proxy_wan` nft láncot használunk, amelyre az `input` lánc **a fail2ban drop után** ugrik;
- a portált **tilos** a Caddy mögé tenni, mert a portál a socket peer IP-jét használja, és minden kliens `127.0.0.1`-nek látszana;
- a Minecraft/nyers TCP nem HTTP, arra a Caddy önmagában nem megoldás; ott DNS SRV rekord és a meglévő portál-szabály a helyes út.

**Kulcsfontosságú invariánsok, amelyek nem sérülhetnek:**

1. A `forward` lánc továbbra is fail-closed marad; a publikus proxy csak a kifejezetten engedélyezett 80/443-at nyitja.
2. Egy fail2ban ban a publikus 80/443-at is lezárja; csak a portál és a DHCP marad elérhető.
3. A host SSH továbbra is csak aktív, engedélyezett portál-munkamenettel érhető el, és csak akkor, ha a munkamenethez egy kifejezetten TCP 22-t engedélyező host (`input`) szabály van rendelve; egyedi teljes hozzáférésű és gyűjtőszabályok nem nyitják meg.
4. Ha a portál vagy a Caddy nem indul el, semmilyen új hozzáférés nem nyílik ki.
5. A proxy konfigurációja admin-only, és nem vezethető be a portál state-jébe vagy a Caddy admin API-ba illetéktelenül.

---

## 2. Kiindulási állapot és korlátok

### 2.1. Hálózati és tűzfalmodell

- A Dropjak konténer `network_mode: host` módban fut (`docker-compose.yml:16`), `read_only: true` (`:21`), `cap_drop: ALL` mellett csak `NET_ADMIN`, `NET_BIND_SERVICE`, `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETUID`, `SETGID` képességeket kap (`:27-36`). A state egy Docker volume-ban van (`:121-122`), a healthcheck a `/api/status`-t pollozza (`:133-138`).
- Az nftables tábla `input` és `forward` lánca is `policy drop` (`deploy/hatarvedelem.nft:114-116`, `:133-137`). A `forward` prioritása -10, hogy a Docker saját szabályai előtt fusson.
- A dinamikus halmazok (`allowed_v4`, `allowed_tcp`, `allowed_udp`, `allowed_icmp`, `allowed_input_tcp`, `allowed_input_udp`, `client_mac`) kernel-timeouttal járnak le; minden restart üríti őket (`README.md:21-31`).
- A pre-auth és block szabályok a `forward` láncon, illetve a `preauth`/`block`/`preauth_nat`/`block_nat` custom láncokban élnek (`deploy/hatarvedelem.nft:109-112`, `gateway.py:1839-1954`). A pre-auth WAN-irányban csak DNAT-olt forgalomra illeszkedik (`ct status dnat`, `gateway.py:1919-1927`).
- A DNAT előtti portot a rendszer `ct original proto-dst` segítségével nézi (`deploy/hatarvedelem.nft:198-200`), mert a Docker saját DNAT-ja ugyanabban a prerouting szakaszban futhat.
- A Docker `DOCKER-USER` láncában egy guard csak a `FWD_MARK` jelöléssel ellátott csomagokat engedi át, minden mást eldob (`docker/entrypoint.sh:160-222`). Ez akkor is véd, ha a `hatarvedelem` tábla eltűnik.
- A LAN felől a 80-as TCP a portálra van átirányítva (`deploy/hatarvedelem.nft:372`); az átirányítás `iifname "__LAN_IF__"` feltétellel csak a LAN interfészre illeszkedik.
- A WAN → LAN forgalom masquerade-el (`deploy/hatarvedelem.nft:375-377`).
- Az IPv6 bejövő forgalmat az `input` és a `forward` lánc is eldobja (`deploy/hatarvedelem.nft:147-148`, `:256-257`).

### 2.2. Fail2ban és portal-viselkedés

- A `banned_v4` drop a `forward` láncban az engedélyező szabályok előtt van (`deploy/hatarvedelem.nft:168-169`).
- Az `input` láncban a portál-elfogadás a ban drop **előtt** szerepel (`deploy/hatarvedelem.nft:279-280`), hogy a tiltott kliens is láthassa a ban-képernyőt; a ban drop ezután következik (`:281-282`). Minden más host-szolgáltatás és a forward-forgalom tiltás alatt eldobódik.
- A portál a socket peer IP-jét használja: `_client_ip()` (`server.py:72-76`). Nincs `X-Forwarded-For` támogatás.
- Az admin API `_admin_guard`, `_origin_ok` (`server.py:93-105`) és JSON-only body (`server.py:143-163`) védelmet használ; a settings módosítás mintája `_admin_settings_action` (`server.py:675-743`): admin guard → origin check → lock → `settings.prepare` → `gw.apply_settings` → audit, hiba esetén 400/503, a state változatlan.
- A `Gateway.apply_settings()` (`gateway.py:4228-4272`) először nftables-be alkalmaz, majd commitol; commit-hiba esetén visszaállítja az előző szabályokat. Ez a minta követendő a proxy beállításoknál is.
- A `Gateway.start()` (`gateway.py:4274-4279`) indítja a reaper, audit és drop log szálakat; ide illeszkedik egy proxy reconciler szál is.

### 2.3. Jelenlegi UI és state

- Az admin navigáció a Users/Groups/Rules/Sessions/Firewall/Drops/Fail2ban/Logs/Settings füleket tartalmazza (`index.html:934-942`).
- A Settings fül két szekciót kezel: pre-auth és block (`README.md:246-266`); a UI a `settingsData()`, `renderSettingForm()`, `renderSettingSection()` és `renderSettings()` függvényekre épül (`index.html:4773-5004`). A host SSH nem beállítás: csak a felhasználóhoz rendelt, TCP 22-t kifejezetten engedélyező host szabály nyitja meg.
- A tab-dispatch `index.html:6314-6321`, a HU/EN/DE i18n táblák ugyanabban a fájlban vannak; a raw firewall nézet lánccímkéi `index.html:5596-5599`.
- A `settings_store.py` validálja és atomikusan írja a `firewall-settings.json`-t (`:126-196`, `:199-366`); korrupt fájl esetén üres pre-auth/block listára esik vissza (fail-closed).
- A state volume tartalma: `users.json`, `groups.json`, `rules.json`, `audit.jsonl`, `drops.jsonl`, `fail2ban.json`, `firewall-settings.json` (`README.md:268-282`).
- A portál plain HTTP-n fut; TLS-t jelenleg külső reverse proxyval vagy trusted management hálózattal kell megoldani (`README.md:293-296`).

### 2.4. Korlátok

- A host SSH portal-gated, és csak a felhasználóhoz rendelt, TCP 22-t kifejezetten engedélyező host szabállyal nyílik meg; egyedi teljes hozzáférésű vagy gyűjtőszabály nem nyitja meg. A proxy integráció nem nyithat management hozzáférést.
- A fail-closed modell nem lazítható; a proxy csak külön, kifejezetten engedélyezett publikus portokat nyithat.
- A kutatás read-only volt; a jelen dokumentum is terv, nem implementáció.
- A `docs/` könyvtár a dokumentummal jött létre; más fájl nem változott.

---

## 3. Architektúra-opciók

### A) Külön Caddy konténer, `network_mode: host`, Admin API-val (javasolt)

A Caddy a host hálózatában figyel a 80/443-on; a portál ugyanabban a hálózati névtérben éri el a `127.0.0.1:2019` admin API-t.

**Előnyök:**

- A WAN 80/443 host-local forgalom, tehát az `input` hookon megy; nem kell DNAT, `FWD_MARK` vagy `DOCKER-USER` integráció.
- A kliens forrás-IP-je végig megmarad, ezért a `banned_v4` drop, a drop log és a fail2ban változatlanul működik.
- A Caddy eléri a Docker által publikált portokat (`127.0.0.1:<hostport>`) és a konténerhálózatokat; a host → konténer forgalom nem megy át a `forward`/`DOCKER-USER` láncon.
- A portál és a Caddy életciklusa szétválik: a portál restartja nem dobja le a publikus oldalakat, a Caddy frissítése nem érinti a portal state-et.
- Nincs Docker socket mount, nincs közös fájlrendszer, nincs `docker exec`.

**Hátrányok:**

- A host network miatt a Caddy minden host-portot és konténer-IP-t elér (SSRF-jellegű kockázat); konfig-validációval és tiltólistával kell fékezni.
- A 80/443 kötéshez root vagy `NET_BIND_SERVICE` kell.
- Az admin API loopbacken hitelesítés nélkül hallgat; a hoston futó bármely folyamat átkonfigurálhatja (2. fázisban Unix socket).

### B) Külön Caddy konténer bridge hálózaton, publikált 80/443-mal

**Előnye:** izoláltabb konténer, nem root a host hálózatában.

**Hátrányai:**

- A publikált portok DNAT-ja miatt a forgalom a `forward` láncon megy; a meglévő pre-DNAT portillesztés (`deploy/hatarvedelem.nft:198-200`) és a `DOCKER-USER` guard (`docker/entrypoint.sh:160-222`) közé kell illeszteni egy újabb kivételt.
- A Caddy nem éri el `127.0.0.1:<publikált port>`-ot, csak a host IP-jét vagy a konténer-IP-t, ami hairpin/NAT-függő.
- Több mozgó alkatrész, több hibaablak.

**v1-re nem javaslom.**

### C) Caddy beépítése a Dropjak image-be

**Hátrányai:**

- A portál konténerének `NET_ADMIN`-ja és state volume-a összekeveredik egy internetre néző TLS-terminátorral.
- A Caddy és a portál upgrade-je összekapcsolódik.
- A portál restartja a publikus oldalakat is ledobja.
- Az image mérete és támadási felülete nő.

**Nem javaslom.**

### D) Saját config-generálás fájlba + `caddy reload`

Ugyanaz a config-generálás, mint A-nál, de a Caddyfile egy megosztott volume-ra kerül, és a portál `docker exec`/signal útján reloadol. Ez plusz jogosultságot (Docker socket vagy exec) és nem atomikus reloadot igényel. **Az Admin API `POST /load` atomikus, hiba esetén az előző config marad érvényben** — ezért A-nál maradunk.

### E) Egy Caddy per host

Egy példány elegendő; a Caddy több site-ot és route-ot is kiszolgál. Több példány csak izoláció/multi-tenant esetén lenne indokolt, ami nem cél.

### Összehasonlítás

| Szempont | A) host + Admin API | B) bridge + publikált port | C) beépített | D) fájl + reload |
|---|---|---|---|---|
| nft complexity | alacsony (input accept) | magas (DNAT, FWD_MARK, DOCKER-USER) | alacsony | alacsony |
| Forrás-IP megmarad | igen | igen | igen | igen |
| Host-local upstream | igen | nem/néha | igen | igen |
| Életciklus-izoláció | jó | jó | rossz | jó |
| Atomic reload | igen | igen | igen | nem |
| Extra jogosultság | nincs | nincs | image merge | Docker socket/exec |
| v1 javasolt | **igen** | nem | nem | nem |

**Döntés:** A) opció, külön compose service-ként, pontos verzióra pinnelt image-dzsel, a Dropjak portál pedig a Caddy admin API kliense.

---

## 4. Domain → port mapping: UI, tárolás, generálás, reload

### 4.1. Adatmodell és tárolás

Új state fájl a meglévő minta szerint: `proxy-settings.json` a state volume-ban (`/var/lib/hatarvedelem`), mode `0600`, atomikus írás (`mkstemp` + `fsync` + `os.replace`), a `settings_store.py:199-366` mintájára.

```json
{
  "version": 1,
  "enabled": true,
  "acme_email": "admin@example.com",
  "acme_staging": false,
  "routes": [
    {
      "id": "r-1a2b3c4d",
      "label": "Nextcloud",
      "host": "cloud.example.com",
      "upstream": "127.0.0.1:8080",
      "enabled": true
    }
  ]
}
```

Validáció a `settings_store.py:126-162` mintájára:

- `host`: kötelező, lowercase FQDN, szigorú regex (csak `a-z0-9.-`, legalább egy pont, max 253 karakter), nincs wildcard, nincs port, nincs séma/útvonal; tiltott a `localhost`, a portal hostneve és a Caddy admin hostja. Ez egyben a Caddyfile-injekció elleni védelem.
- `upstream`: `host:port` alak, host = IPv4 vagy Docker-konténer-név/IP, port 1-65535; tiltott a `169.254.0.0/16`, a `0.0.0.0`, a multicast, valamint a `127.0.0.1:22`, `:53`, `:67`, `:68`, `:2019`, `:8100` (portál) és a host SSH-port. A tiltólista kódban legyen, ne a UI-ban.
- `id`: a meglévő `_ID_RE` minta szerint; `label` max 64 karakter.
- Duplikált `host` nem lehet; a `routes` max ~64 elem.
- Korrupt/hiányzó fájl → **fail-closed**: `enabled=false`, üres route-lista, auditbejegyzés; a portál megpróbál üres Caddy-configot alkalmazni.

### 4.2. Admin API

Új admin endpointok, a meglévő mintát követve (`server.py:675-743`):

- `GET /api/admin/proxy` → a tárolt state + Caddy-státusz (`reachable`, `last_apply_ok`, `last_error`).
- `POST /api/admin/proxy` → `{"action":"save", "enabled":..., "acme_email":..., "acme_staging":..., "routes":[...]}`; opcionálisan `{"action":"sync"}` az újraalkalmazáshoz.
- Kötelező: `_admin_guard`, `_origin_ok` (`server.py:93-105`), JSON-only body (`_read_json`, `server.py:143-163`), külön `proxy_lock`, audit (`admin_proxy_changed`, `admin_proxy_apply_failed`). Hibánál 400 (validáció) vagy 503 (Caddy nem elérhető), a state nem perzisztálódik.

### 4.3. Caddyfile-generálás

A portál a validált state-ből állítja elő a szöveget; nem sablonoz nyers felhasználói stringet.

```caddyfile
{
	admin 127.0.0.1:2019
	email admin@example.com
	# csak staging módban:
	acme_ca https://acme-staging-v02.api.letsencrypt.org/directory
	servers {
		protocols h1 h2
		strict_sni_host on
	}
}

cloud.example.com {
	reverse_proxy 127.0.0.1:8080
}
```

- `protocols h1 h2`: a HTTP/3 (UDP 443) kikapcsolása v1-ben, így nem kell UDP 443-at nyitni.
- Nincs catch-all site és nincs default upstream: ismeretlen Host/SNI nem kap route-ot.
- A `reverse_proxy` automatikusan kezeli a WebSocketet, beállítja az `X-Forwarded-For/Proto/Host` fejléceket, és alapból figyelmen kívül hagyja a kliens által küldött XFF-et.

### 4.4. Alkalmazás, reload, rollback

1. validáció → Caddyfile renderelése;
2. `POST http://127.0.0.1:2019/load`, `Content-Type: text/caddyfile`, rövid timeout (5 s);
3. siker esetén a `proxy_wan` nft lánc frissítése (lásd 5. pont), majd a `proxy-settings.json` atomikus commitja;
4. bármely lépés hibája esetén a korábbi Caddyfile és a korábbi nft-állapot visszaállítása, a state változatlan marad.

Induláskor a Caddy a portál után indul (`depends_on: hatarvedelem: condition: service_healthy`), ezért a `prepare()` alatt még nem elérhető. A `Gateway.start()` (`gateway.py:4274-4279`) mellé kerüljön egy **reconciler thread**: exponenciális backoffal próbálja alkalmazni a kívánt configot, majd periodikusan (pl. 60 s) ellenőrzi az elérhetőséget. A Caddy `/config` autosave-je miatt egy Caddy-restart a legutóbbi alkalmazott configot állítja vissza; a portál csak akkor divergál, ha a Caddy éppen állt, amikor a beállítás változott — ezt a sikertelen apply jelzi, és a reconciler pótolja. A részletes működéshez a Caddy `/data` és `/config` volume-ja kötelező.

### 4.5. UI

Új admin fül a meglévő navigációban (`index.html:934-942`), a Settings mintájára (`index.html:4773-5004`):

- master enable;
- ACME email;
- staging checkbox;
- route-tábla: host, upstream, enabled, állapot;
- add/edit/delete;
- Caddy-státusz és utolsó hiba.

A tab-dispatch (`index.html:6314-6321`) és a HU/EN/DE i18n táblák bővítendők. A Firewall → Raw rules nézetben az új `proxy_wan` lánc címkéje is megjelenik (`index.html:5596-5599`, `gateway.py:160-170`).

### 4.6. Tárolt adatok és backup

A `proxy-settings.json` a state volume része, ezért a meglévő backup eljárásba illeszkedik (`README.md:268-282`). A Caddy saját volume-jai (`caddy-data`, `caddy-config`) külön kezelendők; a `deploy/hv backup` és a dokumentáció egészüljön ki velük. A `/data` ACME account kulcsot és privát tanúsítványkulcsokat tartalmaz, ezért a backupot titkosítani kell.

---

## 5. nftables-terv

### 5.1. Miért input, és nem DNAT

Mivel a Caddy host networkben fut, a WAN 80/443 **a host saját címére** érkezik, tehát az `input` hookon megy. A meglévő WAN pre-auth szabályok (`ct status dnat`, `gateway.py:1919-1927`) csak DNAT-olt forgalomra illeszkednek, ezért a Caddyra nem vonatkoznak. Bridge-es Caddy esetén kellene DNAT + `FWD_MARK` + `DOCKER-USER`, de azt elvetettük.

### 5.2. Új lánc

A sablonban a meglévő custom láncok mellé (`deploy/hatarvedelem.nft:109-112`):

```nft
add chain inet hatarvedelem proxy_wan
```

A sablon betöltése **nem** üríti (mint a preauth/block láncokat), a portál `clear_proxy()`/`apply_proxy()` függvénye kezeli, és a `RULESET_CHAINS` tuple-be (`gateway.py:160-170`) is bekerül a raw view miatt.

### 5.3. Beszúrási hely az input láncban

A kulcs a sorrend. A jelenlegi input láncban a portál-elfogadás a ban drop **előtt** van (`deploy/hatarvedelem.nft:279-280`), a ban drop pedig `:281-282`. Az új jump **a 282. sor után** kerüljön:

```nft
# fail2ban drop után: a tiltott forrás a publikus 80/443-at sem érheti el
iifname "__WAN_IF__" jump proxy_wan
```

A `proxy_wan` lánc alapból üres. Ha a proxy ki van kapcsolva, vagy nincs enabled route, a lánc üres marad → a `policy drop` érvényesül, semmi nem nyílik ki. Ha aktív:

```nft
add rule inet hatarvedelem proxy_wan iifname "__WAN_IF__" tcp dport 80 accept
add rule inet hatarvedelem proxy_wan iifname "__WAN_IF__" tcp dport 443 accept
```

- **Fail2ban precedence:** mivel a jump a `banned_v4 drop` után van, egy banned IP a publikus oldalakat sem éri el. Ez a kötelező invariáns; a jumpot **tilos** a 281. sor elé tenni. A meglévő preauth minta is ezt erősíti: a preauth lánc első szabálya szintén a ban drop (`gateway.py:1861-1864`).
- **LAN redirect:** a portál-átirányítás `iifname "__LAN_IF__" ... tcp dport 80 redirect to :__PORT__` (`deploy/hatarvedelem.nft:372`), tehát csak a LAN interfészre illeszkedik; a WAN 80-at nem érinti. LAN felől a HTTP továbbra is a portálra megy.
- **LAN 443:** ha a belső kliensek is el akarják érni a publikus route-okat a publikus IP-n (hairpin), kell egy `iifname "__LAN_IF__" tcp dport 443 jump proxy_wan` is; ez nem ad több jogot, hiszen ugyanaz a szolgáltatás WAN-ról amúgy is publikus. v1-ben javaslom ezt kapcsolóval, alapból **kikapcsolva**, és dokumentálva, hogy LAN HTTP-re továbbra is a portál válaszol.
- **Pre-auth/block szemantika:** ezek a szabályok a `forward` láncon élnek, host-local Caddyra nem hatnak. A block lista tehát **nem** tiltja a publikus proxy route-ot; ezt dokumentálni kell, mert félrevezető lehet. A pre-auth listára sem kell felvenni a proxyt.
- **Docker-USER guard:** nem érintett. A host-local 80/443 input, a Caddy host → konténer upstream forgalma pedig lokálisan generált, nem megy át a `forward`/`DOCKER-USER` láncon. A guard (`docker/entrypoint.sh:160-222`) változatlan marad.
- **Drop-log/fail2ban viselkedés:** a WAN 80/443 eddig `input-wan` drop eseményt termelt, és a drop-alapú banning látta a portscannereket. Ezután ezek a csomagok átjutnak a Caddyhoz, így a drop-alapú ban nem fogja látni őket. A login brute-force és a többi drop ok változatlan. 2. fázisban a Caddy access logból lehet fail2ban-integrációt építeni.
- **IPv6:** az input lánc IPv6-dropja (`deploy/hatarvedelem.nft:256-257`) miatt a Caddy csak IPv4-en érhető el. A DNS-ben **ne** legyen AAAA rekord a proxy hostnevekhez, különben az IPv6-preferáló kliensek falba futnak. Az IPv6 külön projekt.
- **Natív telepítés:** az `install.sh` alapértelmezett `PORT=80`-ja ütközik a Caddy 80-as kötésével. A Caddy-integráció v1-ben Docker-compose módot feltételez; natív módban a portált át kell állítani, vagy a Caddy nem indul.
- **Portál leállása:** a nft szabályok a kernelben maradnak, a publikus route-ok tovább élnek; ez a publikus szolgáltatásoknál elfogadható. A portál újraindulásakor a `prepare()`/`_apply_custom_settings()` a perzisztált állapotból újraalkalmazza a `proxy_wan` láncot; korrupt state esetén üres lánc (fail-closed).

### 5.4. Fail-closed viselkedés

- Ha a `proxy-settings.json` nem létezik vagy korrupt: `enabled=false`, üres `proxy_wan` → a 80/443 a `policy drop` miatt zárva.
- Ha a Caddy nem indul el, a portál a `proxy_wan` láncot akkor sem nyitja ki, ha a state enabled; az apply lépés a Caddy hibájánál megszakad, és a state nem commitolódik.
- Ha a portál meghal, a kernelben maradt szabályok érvényben maradnak; a Caddy a legutóbbi jó configot szolgálja ki. Új route nem keletkezik.
- A template reload nem üríti a `proxy_wan` láncot, ugyanúgy, ahogy a preauth/block láncokat sem (`deploy/hatarvedelem.nft:102-112`).

---

## 6. ACME / SSL

### 6.1. DNS-követelmények

- Minden route-hoz publikus **A rekord** a WAN IP-re. A rekordot a tanúsítvány kiadása előtt kell beállítani; a HTTP-01/TLS-ALPN-01 a kiadás pillanatában már elérhető hostnevet igényel.
- **AAAA rekord nem javasolt**, mert az IPv6 bejövő forgalmat az nft eldobja (`deploy/hatarvedelem.nft:256-257`). Ha a hostnévhez AAAA is tartozik, az IPv6-preferáló kliensek nem érnek el semmit.
- **CAA:** ha van CAA rekord, engedni kell a `letsencrypt.org`-ot; a Caddy alapból Let's Encrypt, hiba esetén ZeroSSL felé esik vissza, ezért vagy mindkettőt engedjük, vagy `acme_ca`-val rögzítsük a Let's Encryptet.
- A DNS-t a proxy bekapcsolása előtt kell beállítani, különben a Caddy a rate limitet fogyasztja sikertelen authorizációkkal.

### 6.2. Challenge-típusok

- **HTTP-01:** a 80-as porton; a Caddy automatikusan kiszolgálja.
- **TLS-ALPN-01:** a 443-as porton; a Caddy automatikusan kiszolgálja.
- A kettő alapból aktív; a 80 és 443 nyitva kell legyen (a `proxy_wan` szabályok). Ha a 80-at a szolgáltató blokkolja, a TLS-ALPN-01 önmagában is elég.
- **DNS-01:** csak wildcardhoz vagy olyan esethez, amikor a 80/443 kívülről nem elérhető. A hivatalos Caddy image **nem tartalmaz** DNS-provider modult; xcaddy-vel kell custom buildet készíteni (pl. `github.com/caddy-dns/<provider>`), plusz API-token secret. Ez 2. fázis.

### 6.3. Wildcard

- A `*.example.com` csak DNS-01-jel kiadható.
- A wildcard csak egy bal oldali címkét fed (`*.example.com`, nem `a.b.example.com`).
- A Caddy 2.10+ a wildcard certet konfigurált subdomainekhez újra tudja használni, ami csökkenti a kiadások számát.
- A standard image helyett custom build kell; a DNS API tokent secretként kell tárolni, nem a `proxy-settings.json`-ban.

### 6.4. Megújítás és tárolás

- A Caddy automatikusan, a lejárat előtt kb. egyharmaddal újít; nincs szükség cronra.
- Feltétel a perzisztens `/data` volume (ACME account kulcs + certek). Ha a volume elveszik, az újrakiadás a rate limitbe számít.
- A `/config` volume a Caddy autosave-jét tárolja; e nélkül egy restart után nem áll vissza a legutóbbi config.
- A `/data` privát kulcsokat tartalmaz; a volume jogosultsága 0700, a backup titkosított.

### 6.5. Email és staging

- Az ACME email ajánlott (lejárati értesítések), nem kötelező.
- Teszteléshez `acme_ca https://acme-staging-v02.api.letsencrypt.org/directory`; a staging cert nem bízható meg, élesítéskor vissza kell kapcsolni és újra kiadni.
- A staging toggle legyen a UI-ban, hogy véletlenül se éles rate limitet égessünk el.

### 6.6. Rate limitek

| Limit | Érték |
|---|---|
| Tanúsítvány / registered domain / 7 nap | 50 |
| Azonos identifier-set / 7 nap | 5 |
| Új order / account / 3 óra | 300 |
| Sikertelen authorization / identifier / account / óra | 5 |
| Account / IP / 3 óra | 10 |
| Caddy saját kísérleti limit | 10 / account / 10 s |

Élesítés előtt staging; a sikertelen kísérletek a fenti limiteket fogyasztják.

### 6.7. On-demand TLS

v1-ben **nem** használjuk. Ha valaha bekerül, csak `on_demand_tls { ask ... }`-vel, különben a rate limit kimeríthető, és a proxy nyitott tanúsítványgyárrá válik.

### 6.8. HTTP → HTTPS és a portál

- A Caddy a 80-on automatikusan HTTPS-re irányít; ez WAN-ról működik.
- LAN-on a portál redirectje fut előbb (`deploy/hatarvedelem.nft:372`), ezért LAN HTTP-re a portál válaszol. Ez a captive portal miatt helyes.
- A portálra ne tegyünk HSTS-t, mert a portál plain HTTP-n fut (`README.md:293-296`).

### 6.9. Minecraft és nyers TCP

- A Caddy HTTP reverse proxy **nem** tud Minecraft-protokollt kiszolgálni, és „auto SSL” sem értelmezhető rá.
- A Minecrafthoz DNS SRV rekord (`_minecraft._tcp.play.example.com` → host:25565) + a meglévő portál-szabály/preauth a helyes út; ez a Caddy-integrációtól független.
- Nyers TCP-re a `caddy-l4` plugin létezik, de az nem auto-TLS és nem v1.

---

## 7. Biztonsági kockázatok és mitigációk

1. **Publikus kitettség:** a 80/443 internetre nyílik, a Caddy lesz a legnagyobb támadási felület. Mitigáció: pontos verzióra pinnelt image, rendszeres frissítés, standard (minimal modulos) build, v1-ben nincs `caddy-l4`, nincs catch-all.
2. **SSRF-jellegű upstream:** a host networkös Caddy bármely host-portot és konténer-IP-t elér (SSH, portál, admin API, Docker API, metadata). Mitigáció: admin-only konfiguráció, szigorú host/upstream validáció, tiltólista, nincs default upstream, audit; 3. fázisban dedikált UID + nft output/kimeneti korlátozás.
3. **Admin API hitelesítés nélkül a loopbacken:** bármely helyi folyamat átkonfigurálhatja a Caddyt. v1: single-tenant host, dokumentált feltételezés; 2. fázis: Unix socket (`admin unix//run/caddy/admin.sock`) szűk jogosultsággal, a portál konténerébe mountolva.
4. **A portált NE proxyljuk:** a `_client_ip()` (`server.py:72-76`) kizárólag a socket peer címét használja, XFF-et nem. Ha a portál Caddy mögé kerül, minden kliens `127.0.0.1`-nek látszik, és elromlik a session IP-kötés, a host SSH grant, a fail2ban, a ban-képernyő, valamint az `_origin_ok` (`server.py:93-105`) és a `_portal_host_matches` (`server.py:320-327`). Ha a portálra TLS kell, előbb trusted-proxy XFF-támogatást kell beépíteni (3. fázis), vagy VPN/SSH tunnel használandó.
5. **Header-higiéné:** a Caddy alapból felülírja az XFF-et és figyelmen kívül hagyja a bejövőt; a `trusted_proxies`-t **soha** ne állítsuk `0.0.0.0/0`-ra. A backend ne bízzon vakon az XFF-ben. HSTS-t csak akkor, ha minden érintett név HTTPS-only; a portál domainjére ne tegyünk HSTS-t. 2. fázis: `strict_sni_host on`, biztonsági headerek.
6. **Secret-ek:** a `/data` ACME account kulcsot és cert privát kulcsokat tartalmaz — volume 0700, a backup titkosítva. DNS API token (2. fázis) Docker secretből vagy 0600 `.env`-ből, **soha** ne kerüljön a `proxy-settings.json`-ba vagy az audit logba. A `.env` maradjon 0600 (`README.md:321-323`).
7. **Fail2ban precedence:** a `proxy_wan` jump a ban drop után van; ezt tesztelni kell (a meglévő exact-string tesztek mintájára, `tests/test_gateway.py:3690-3829`), hogy egy ban ne kerülhessen meg.
8. **Drop-alapú banning változása:** a WAN 80/443 már nem termel `input-wan` dropot; a portscannerek a Caddyhoz jutnak. 2. fázisban access-log-alapú fail2ban.
9. **DoS:** a Caddy kezeli a TLS/HTTP terhelést; v1-ben nincs rate limit. 2. fázisban plugin vagy upstream limit.
10. **Konténer-hardening:** `read_only: true`, `cap_drop: ALL` + `NET_BIND_SERVICE`, `security_opt: no-new-privileges:true`, nincs Docker socket, journald log, pontos image pin. A rootként futó Caddy v1-ben elfogadható, 2. fázisban non-root + `setcap` vagy Unix socket.
11. **Backup:** a `deploy/hv backup` és a README backup szakasza (`README.md:268-282`) egészüljön ki a `caddy-data` és `caddy-config` volume-okkal.

### 7.1. Javasolt compose-vázlat

```yaml
caddy:
  image: caddy:<pontos-verzió>
  network_mode: host
  read_only: true
  cap_drop: [ALL]
  cap_add: [NET_BIND_SERVICE]
  security_opt: ["no-new-privileges:true"]
  restart: unless-stopped
  volumes:
    - caddy-data:/data
    - caddy-config:/config
    - /etc/localtime:/etc/localtime:ro
  depends_on:
    hatarvedelem:
      condition: service_healthy
  logging:
    driver: journald
```

A Caddy admin API csak `127.0.0.1:2019`-en hallgasson. A konténer ne kapjon `NET_ADMIN`-t, ne lássa a Docker socketet, és ne kapjon host PID névteret.

---

## 8. Fázisok, MVP és becslések

### 8.1. v1 — minimális, hasznos iteráció

**Scope:**

- külön Caddy konténer host networkben, hardened compose service;
- `proxy-settings.json` + validáció + atomikus írás;
- `proxy_wan` nft lánc + input jump a ban drop után, `clear_proxy`/`apply_proxy`, raw view;
- Caddyfile-render + `POST /load` + rollback + startup reconciler;
- admin API (`GET/POST /api/admin/proxy`) a meglévő guard/origin/lock/audit mintával;
- admin UI fül + HU/EN/DE i18n + route CRUD + staging toggle;
- explicit hostnevek, HTTP upstream, HTTP/1.1+2, WAN-only, nincs wildcard, nincs DNS-01, nincs portal-proxy;
- tesztek: nft exact-string, settings-store validáció/korrupt fallback, API 400/503, Caddyfile renderelés injekciós esetekre;
- dokumentáció (README + `deploy/HELYI-UTMUTATO.md`).

**Kimenő scope:** wildcard, DNS-01, on-demand TLS, HTTP/3, IPv6, portál-proxy, portál-gated route-ok, `caddy-l4`, rate limit, access-log fail2ban.

**Becslés:**

| Terület | Óra |
|---|---|
| nft + gateway (`proxy_wan`, apply/clear, raw view) | 5-7 |
| settings store + validáció | 4-5 |
| Caddyfile render + admin kliens + reconciler | 7-9 |
| API + audit | 4-5 |
| UI + i18n | 8-10 |
| tesztek | 6-8 |
| docs + compose | 3-4 |
| buffer / hardening | 3-7 |
| **Összesen** | **40-55** |

Részcélok:

- **PoC** (csak nft + kézi Caddy config): 12-16 óra.
- **Első hasznos iteráció** (a fenti scope UI-polish és teljes tesztfedés nélkül): 24-32 óra.
- **Teljes, polírozott v1**: 40-55 óra.

### 8.2. 2. fázis — hardening/ops (20-30 óra)

- Unix socket admin, non-root Caddy;
- cert-státusz és Caddy-log a UI-ban;
- access-log + fail2ban;
- wildcard DNS-01 custom build + secret;
- HSTS/security headerek, `strict_sni_host`;
- LAN 443/hairpin kapcsoló;
- backup-integráció;
- rate limit.

### 8.3. 3. fázis — haladó (30-60+ óra)

- portál-gated route-ok (MAC-kötéssel; ehhez a host-input oldali `allowed_tcp` MAC-párosítás hiányzik, ezt pótolni kell);
- on-demand TLS `ask`-kal;
- `caddy-l4` nyers TCP-hez;
- IPv6;
- bridge/skuid izoláció;
- multi-tenant.

---

## 9. Tesztelési terv

- **nft exact-string tesztek:** a `tests/test_gateway.py:3690-3829` mintájára ellenőrizni kell a `proxy_wan` lánc létrehozását, a jump pontos helyét a ban drop után, az accept szabályokat, valamint azt, hogy kikapcsolt proxy esetén a lánc üres.
- **Settings store tesztek:** a `tests/test_gateway.py:3532-3696` mintájára validáció, atomikus írás, korrupt fájl → fail-closed.
- **API tesztek:** a `tests/test_gateway.py:2819-2930` mintájára admin guard, origin check, 400 invalid, 503 Caddy hiba, state változatlan.
- **Caddyfile-injekció:** hostnévbe és upstreamba tett `{`, `}`, newline, `#`, `;` karakterek elutasítása; ismeretlen Host nem kap route-ot.
- **Ban-precedence:** banned IP nem éri el a 80/443-at, de a portált és a DHCP-t igen; a ban levétele után a proxy újra elérhető.
- **Fail-closed:** nincs `proxy-settings.json` → üres `proxy_wan`; Caddy nem elérhető → nincs state-commit; portál restart → a perzisztált állapot újraalkalmazása.
- **Integrációs ellenőrzés:** a 88.198.151.195 teszt VM-en csak egy későbbi, külön jóváhagyott fázisban; a jelen terv nem tartalmaz telepítést.

---

## 10. Nyitott kérdések

1. **Mi a konkrét cél:** publikus HTTP(S) webalkalmazás, vagy Minecraft/nyers TCP? Utóbbi esetén a Caddy-integráció nem indokolt; DNS SRV + portál-szabály a megoldás.
2. **LAN 443 hairpin:** engedjük-e a belső klienseknek a publikus route-okat a publikus IP-n? v1 javaslat: külön kapcsoló, alapból ki.
3. **Korrupt `proxy-settings.json`:** üres route-lista (fail-closed) vagy a Caddy utolsó jó configjának megtartása? v1 javaslat: fail-closed, auditált.
4. **Natív telepítés:** támogatott-e a Caddy natív módban, vagy csak Docker compose? v1 javaslat: csak Docker.
5. **Admin API:** marad-e a `127.0.0.1:2019`, vagy Unix socket? v1: loopback; 2. fázis: socket.
6. **HTTP/3:** kikapcsolva v1-ben; később UDP 443 nyitással.
7. **Portál proxylása:** nem javasolt; ha mégis kell, előbb trusted-proxy XFF támogatás a portálban.

---

## 11. Ajánlás

**Feltételesen igen.** Ha a cél az, hogy publikus HTTP(S) szolgáltatásokat (webapp, dashboard, API) domain/subdomain alatt, automatikus tanúsítvánnyal tegyünk elérhetővé, akkor a javasolt architektúra illeszkedik a Dropjak modelljéhez, és a fail-closed/precedencia invariánsok betarthatók. Ha a konkrét cél a Minecraft (vagy más nyers TCP) publikálása, akkor a Caddy nem megoldás: ott DNS SRV + a meglévő portál-szabály a helyes út, és a Caddy-integrációt nem érdemes elkezdeni.

**Elsőként ezt érdemes megépíteni:**

1. a `proxy_wan` nft lánc + input jump a ban drop után (ez a legkisebb, önállóan tesztelhető biztonsági gerinc);
2. a külön Caddy konténer + admin API-s Caddyfile-apply + rollback;
3. a `proxy-settings.json` + minimális admin UI/API;
4. csak ezután a kényelmi és ops-funkciók.

**Amit v1-ben ne tegyünk:**

- Caddy beépítése a Dropjak image-be;
- bridge-es Caddy;
- a portál proxylása;
- wildcard/DNS-01;
- on-demand TLS;
- catch-all route;
- HTTP/3 (UDP 443);
- a `proxy_wan` jump a ban drop elé helyezése.

---

## 12. Függelék — hivatkozott fájlok és sorszámok

| Fájl | Relevant részek |
|---|---|
| `/home/moodpatcher/hatarvedelem/README.md` | 21-23 (fail-closed), 31-34 (host SSH), 35-39 (Docker), 40-49 (fail2ban), 50-53 (host network), 246-266 (settings), 268-282 (backup), 293-296 (TLS), 302-320 (security) |
| `/home/moodpatcher/hatarvedelem/docker-compose.yml` | 16 (host network), 21 (read_only), 27-36 (caps), 43-119 (env), 121-122 (state volume), 133-138 (healthcheck) |
| `/home/moodpatcher/hatarvedelem/deploy/hatarvedelem.nft` | 109-112 (custom chains), 114-116 (input policy), 133-137 (forward policy), 147-148 (IPv6 forward), 168-169 (ban forward), 198-200 (pre-DNAT matching), 256-257 (IPv6 input), 279-282 (portal accept + ban drop), 313 (established), 324-325 (portal accept), 334 (host SSH), 342-345 (DNS), 349-350 (final logs), 372 (LAN redirect), 375-377 (masquerade) |
| `/home/moodpatcher/hatarvedelem/gateway.py` | 160-170 (`RULESET_CHAINS`), 1823-1837 (`clear_custom`), 1839-1954 (`apply_custom`), 1861-1864 (preauth ban drop), 4228-4272 (`apply_settings`), 4274-4279 (`start`) |
| `/home/moodpatcher/hatarvedelem/settings_store.py` | 126-162 (validáció), 148-154 (TCP 80 block), 165-196 (`validate_state`), 199-366 (store) |
| `/home/moodpatcher/hatarvedelem/server.py` | 72-76 (`_client_ip`), 93-105 (`_origin_ok`), 143-163 (`_read_json`), 234-254 (`_admin_state`), 320-327 (`_portal_host_matches`), 675-743 (settings action), 846-869 (POST routes), 1852-1930 (`_serve`) |
| `/home/moodpatcher/hatarvedelem/index.html` | 934-942 (admin nav), 4773-5004 (settings UI), 5596-5599 (chain labels), 6314-6321 (tab dispatch) |
| `/home/moodpatcher/hatarvedelem/docker/entrypoint.sh` | 98-158 (ruleset render), 160-222 (DOCKER-USER guard), 252-280 (firewall load) |
| `/home/moodpatcher/hatarvedelem/deploy/hatarvedelem-boot.nft` | boot guard; az input policy accept, amíg a fő tábla nem töltődik |
| `/home/moodpatcher/hatarvedelem/tests/test_gateway.py` | 2819-2930 (settings API), 3532-3696 (settings store), 3690-3829 (nft exact-string) |

---

*Vége — ez a dokumentum terv, nem implementáció.*
