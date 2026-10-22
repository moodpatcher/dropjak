# Domain proxy – fejlesztési és telepítési napló

**Utolsó frissítés:** 2026-10-22 01:10
**Teszt VM:** 88.198.151.195 (Debian 13, Docker)
**Élő verzió:** 3.9.1 (élesítve: 2026-10-22).
**Utolsó commit:** `62cdabc` (3.6.0, a GitHubra feltöltve). A 3.7.0 és 3.9.1 közötti változások nincsenek commitolva.
**Folyamatban:** 3.10.0 (a kikapcsolt automatikus tanúsítvány javítása, élesítés alatt) és 3.11.0 (Proxy fül, TCP/UDP port proxy; helyben kész, nincs élesítve).

---

## Áttekintés

A Dropjak kapott egy beépített, Caddy-alapú reverse proxyt. A gyökérdomain alatti aldomaineket (például `teszt1.z2.moodpatcher.com`) a tűzfal mögötti szolgáltatásokra továbbítja, automatikus vagy feltöltött HTTPS-tanúsítvánnyal. A hozzáférésről a Dropjak dönt: belépés, domain típusú szabályok, láthatóság, challenge és fail2ban alapján.

### Architektúra

- **Caddy:** külön konténer, `network_mode: host`, `caddy:2.10.2-alpine`, compose profil `proxy`. Fix `deploy/Caddyfile`, admin API nélkül; menet közben nincs újratöltés.
- **Döntés:** minden HTTP-kérésnél `forward_auth` hívja a portál `/api/proxy/auth` végpontját.
  - Engedély esetén a portál a `X-Dropjak-Upstream` fejlécben adja meg a célt, a Caddy erre proxyz.
  - Ha nincs engedély, a válasz 401 (tiltó oldal) vagy 403 (challenge).
- **Tanúsítványok:**
  - A `get_certificate http` → `/api/proxy/cert` a feltöltött tanúsítványt szolgálja ki.
  - Ha nincs feltöltött, on-demand ACME jön. Ezt a `/api/proxy/ask` engedélyezi, csak felvett nevekre.
- **Kliens-IP:** a Caddy a valódi IP-t az `X-Forwarded-For` fejlécben küldi. A portál ezt csak loopback (127.0.0.1/::1) peertől fogadja el.
- **Tűzfal (nft):** TCP 80/443 csak `HV_PROXY=1` mellett nyílik meg, a fail2ban-drop után.
  - WAN felől mindenkinek.
  - LAN felől csak IP+MAC-kötött klienseknek.
- **Bekapcsolás (`.env`):** `HV_PROXY=1` és `COMPOSE_PROFILES=proxy`.

### DNS (alapfeltétel)

- Két `A` rekord kell: `z2.moodpatcher.com` és `*.z2.moodpatcher.com` → 88.198.151.195.
- Cloudflare-en „DNS only” (szürke felhő), AAAA rekord nélkül.
- A `z1.moodpatcher.com` Cloudflare-proxys, ezért nem használható. A `z2` használatban van.

---

## Verziók

### 3.4.0 – az alap proxy (élesítve)

- Caddy szolgáltatás, statikus Caddyfile, on-demand TLS az `ask` végponttal.
- `/api/proxy/ask`, `/api/proxy/auth`, `/api/proxy/unauthorized.png`. Csak a loopback hívhatja őket.
- Tiltó oldal az `unauthorized.png` képpel és egy „Bejelentkezés” gombbal.
- Beállítások: `proxy_domain` és `proxy_routes` (aldomain → port).
- nft: `__PROXY__` sablon-placeholder a 80/443 accept szabályokhoz.
- Telepítve. Mentés: `hatarvedelem-20261021-165039.tar.gz`. A `.env` két új sort kapott.

### 3.5.0 – Domainek fül, input/forward, domain-szabály (élesítve)

- Saját **„Domainek”** admin fül; kikerült a Beállítások alól.
- **Bejegyzéstípusok:**
  - `input`: `127.0.0.1:port`.
  - `forward`: privát IP:port (10/8, 172.16/12, 192.168/16).
- **Új szabálytípus, a „domain”:** felvett hostneveket enged.
  - Nem nyit nft-portot.
  - Felhasználóhoz, csoporthoz és gyűjtőszabályhoz rendelhető.
  - Admin vagy teljes hozzáférésű szabály sem kerülheti meg.
- Olyan bejegyzés, amelyre szabály hivatkozik, nem törölhető és nem nevezhető át.
- Kétsoros bejegyzéskártyák a felületen.

### 3.6.0 – több gyökérdomain, HTTPS portál, láthatóság (élesítve és commitolva: `62cdabc`)

- **Több gyökérdomain** (`proxy_domains`). A bejegyzés azonosítója a teljes hostnév (`név.gyökér`).
- **Migráció:**
  - A régi `proxy_domain` listává alakul.
  - A domain-szabályok rövid nevei teljes hostnevekké alakulnak, mentéssel.
  - A VM-en ellenőrizve: `teszt-access` → `teszt1/2/3.z2.moodpatcher.com`.
- **A Dropjak portál HTTPS-en, minden gyökérdomainen:** `https://z2.moodpatcher.com`, Let's Encrypt tanúsítvánnyal.
  - Az `X-Forwarded-For` fejlécet csak loopback felől fogadja el.
  - A munkamenet-süti `Secure` jelzést kap.
  - A `/api/proxy/*` kívülről, a proxyn át sem érhető el.
- **Láthatóság:** `private` (domain-szabály kell) vagy `public` (bárki megnyithatja).
- Push a GitHubra: csak az `~/.ssh/id_claude_ed25519` kulccsal megy.

### 3.7.0 – fail2ban proxy, tanúsítványok, naplózás, HTTPS-átirányítás (élesítve, nincs commitolva)

- **Fail2ban „proxy” kategória:**
  - X darab 401 egy időablakon belül tiltást vált ki. Alapérték: 20 találat 10 perc alatt.
  - A tiltás csak a 80/443-at zárja, az új `proxy_banned_v4` nft set-tel. A :8100-as portál elérhető marad.
- **Domain beállítások** a Beállítások fülön:
  - kapcsoló az automatikus tanúsítványhoz (`proxy_acme`);
  - tanúsítvány és kulcs feltöltése gyökérdomainenként (`certs/` a state volume-ban, 0600).
  - A kulcs semmilyen API-n vagy naplóban nem jelenik meg.
- **Napló:** `proxy_page_opened` esemény, csak oldalbetöltésnél (a `Sec-Fetch-*` fejlécek alapján).
- **Drop napló:** a proxy 401-ek `proxy-unauthorized` sorként jelennek meg. Nem számítanak bele a csomagalapú fail2ban-jelekbe.
- **HTTPS-átirányítás:** WAN felől a `http://…:8100` címről 308 a `https://<első gyökér>/` címre.
  - Kivétel: LAN, tiltott IP, `/api/`, loopback, illetve ha nincs tanúsítvány.
- Az admin tűzfal nézetében megjelenik a `proxy_banned_v4`.
- **Élesítés:**
  - Új image: `6a1e9656bce9`. Az előző `hatarvedelem:prev-3.6.0` néven megmaradt.
  - Mentés: `hatarvedelem-20261021-210454.tar.gz`.
- **Kívülről ellenőrizve:**
  - a :8100 308-cal továbbít;
  - a `https://z2…` 200-at ad;
  - a `teszt1` 401-et ad.
- **A VM-en is ellenőrizve** (`recreate-20261021-210526.log`): a Caddy az új, `get_certificate`-es Caddyfile-lal fut, a `proxy_banned_v4` set és a 80/443-as drop szabály él, a `.env` nem változott.

### 3.8.0 – challenge (élesítve: 2026-10-22)

- **Bejegyzésenként lenyíló „Challenge (ellenőrzés)” rész, pipákkal:**
  - Első megnyitáskor: 24 órás igazolás.
  - X óránként: 1–720 óra.
  - Naponta első megnyitáskor: helyi éjfélkor jár le.
  - Ha az IP kapott már 401-et: a fail2ban proxy-számlálója alapján.
  - Ha bármely fail2ban-számláló fut rá.
  - Gyanús kliens: hiányzó böngészőfejlécek, vagy curl/wget/szkript User-Agent.
  - Új IP-ről: az igazolás az IP-hez kötött.
- **Challenge oldal:** a tiltó oldal kinézete a `sus.png` képpel, alatta a belépőoldalról ismert „Nem vagyok robot” PoW-mező vagy Turnstile. Más gomb nincs.
  - Nem 401-et, hanem 403-at ad, így a fail2ban nem számolja, és a drop naplóba sem kerül.
  - Az elrontott megoldás viszont számít.
- **Igazolás:**
  - Süti: `__Host-dropjak_pass` (HMAC, Secure, HttpOnly).
  - A Caddy kiszedi, mielőtt a kérés az upstreamhez ér.
  - A kulcsot a folyamat indulásakor véletlenszerűen generálja, ezért a portál újraindulásakor az igazolások érvénytelenné válnak.
- **Végpontok:** `/api/gate/challenge` (GET és POST), a Caddyfile-ban `/__dropjak/challenge` és `/__dropjak/sus.png`.
- **Tesztelve:** valódi Caddy 2.10.2 és fej nélküli Chromium mellett végig. 668 teszt, mind átment.

### 3.8.0 további részei (élesítve, 673 teszt, mind átment)

- **Ismeretlen aldomain** (például `ezbiztosnemletezik.z2…`): mindig challenge jön, siker után átirányítás a `https://z2.moodpatcher.com/` címre.
  - Csak feltöltött wildcard tanúsítvánnyal működik. Ismeretlen névre a rendszer soha nem kér ACME-tanúsítványt (Let's Encrypt rate limit).
  - **Élesben nincs wildcard tanúsítvány** (a VM-en nincs `certs/` könyvtár), ezért a `https://asd.z2…` TLS-hibát ad (`SSL_ERROR_INTERNAL_ERROR_ALERT`). Félreértés volt: a felhasználó nem töltött fel tanúsítványt.
  - Az `a.b.z2…` alakú, kétszintű nevekre a `*.z2…` wildcard nem érvényes.
- **Naplók:** IP-szűrő (pontos cím vagy CIDR), a szerveren szűr, és az `ip`, `target`, `target_ip`, `session_ip` és `request_ip` mezőkre illeszkedik. A proxy-hostnév és az útvonal félkövéren, a sor elején jelenik meg.
- **Dokumentáció:** a két DNS-rekord mint alapfeltétel a README-ben és a `deploy/HELYI-UTMUTATO.md`-ben.
- **„Naponta” trigger:** a `/etc/localtime` csak olvasható csatolásként bekerül a konténerbe, így magyar éjfélkor vált, nem UTC szerint.

---

### 3.8.1 – HTTP-átirányítás a Dropjak döntése alapján (élesítve)

- A 80-as porton a Caddy `forward_auth`-tal a `/api/proxy/redirect` végponttól kérdezi meg, hová irányítson.
  - A gyökérdomain és a létező bejegyzések 308-at kapnak a saját HTTPS-címükre, az útvonal megmarad.
  - Ha egy ismeretlen aldomaint lefed a feltöltött wildcard tanúsítvány, az is 308-at kap.
  - Minden más ismeretlen aldomain, a nyers IP-cím és az idegen Host 302-t kap a `https://<gyökér>/` címre.
- Az ACME-ellenőrző útvonal kivétel, és ha a portál nem érhető el, a Caddy a régi átirányítást adja (`handle_errors`).
- Döntés: ismeretlen aldomainre HTTPS-en TLS-hiba marad, mert wildcard tanúsítvány nincs, és Cloudflare-t nem használunk. A Dropjak-DNS (zóna-delegálás és DNS-01) a Cloudflare kiváltásakor kerül elő újra.
- Élesben ellenőrizve, mind a 9 eset rendben. Új image: `e94d20677d0c`; az előző `hatarvedelem:prev-3.8.0` néven megmaradt. Mentés: `hatarvedelem-20261021-221554.tar.gz`.
- Nyitott kérdés: a VM rendszer-időzónája `Etc/UTC`, ezért a „Naponta” trigger UTC-éjfélkor vált.

### 3.9.0 – „Sok frissítés / spam” challenge-feltétel (élesítve)

- Új pipa (`burst`): ha ugyanaz az IP 30 másodpercen belül 10-szer megnyitja (frissíti) a bejegyzés egy oldalát, új ellenőrzés kell. Az észlelés előtt kiadott igazolás nem számít.
  - Csak az oldalmegnyitás számít, az XHR- és fájlkérés nem. A számláló a portál memóriájában van, IP+hostonként.
- Az új `sus.png` élesben (az md5 egyezik a helyivel).
- Élesben ellenőrizve, mind a 9 eset rendben. Új image: `5a6a54c842a7`; az előző `hatarvedelem:prev-3.8.1` néven megmaradt. Mentés: `hatarvedelem-20261021-223337.tar.gz`.

### 3.9.1 – a `sus.png` igazítása (élesítve)

- A challenge-oldalon a kép 8px-szel balra került, hogy a captchával egy vonalban legyen.
- Élesben ellenőrizve, mind a 9 eset rendben. Új image: `65f64fe9833e`; az előző `hatarvedelem:prev-3.9.0` néven megmaradt. Mentés: `hatarvedelem-20261021-224148.tar.gz`.

### 3.10.0 – a kikapcsolt automatikus tanúsítvány valóban kikapcsol (helyben kész, élesítésre vár)

- **Hiba (élesben, 3.9.1):** a Domain beállításokban kikapcsolt automatikus tanúsítvány után a Let's Encrypt-tanúsítványok továbbra is kiszolgálódtak, minden bejegyzésen és a gyökéren (a Dropjak felületén) is.
- **Felhasználói elvárás:** „ha valaki nem akar auto certet, akkor ne piszkálj bele a certekbe”. Kikapcsolt állapotban csak a feltöltött tanúsítvány él; ahol nincs ilyen, ott TLS-hiba van.
- **Ok (forrásból ellenőrizve, certmagic v0.24.0 = Caddy 2.10.2):**
  - `handshake.go` `getCertDuringHandshake`: a sorrend memória-gyorsítótár → `get_certificate` (feltöltött) → `ask` → betöltés a `/data`-ból → új kérés. A gyorsítótár-találat előtt semmi nem kérdezi az `ask`-ot.
  - A `/data`-ból betöltés előtt a `checkIfCertShouldBeObtained` meghívja az `ask`-ot; kikapcsolt kapcsolónál ez 404, így újraindulás után semmi nem töltődik be. A hiba tehát csak a memóriában élt.
  - Caddy `modules/caddytls/tls.go` `Cleanup`: újratöltéskor csak a statikusan kezelt (`managing`) és betöltött (`loaded`) neveket veszi ki a gyorsítótárból, az on-demand tanúsítványokat nem. Újratöltés tehát nem segít, újraindítás kell.
- **Megoldás (kisebb, mint a terv):**
  - A Caddyfile statikus maradt; generált JSON és konfiguráció-push nem kell, mert kikapcsolt kapcsolónál az `ask` már most is minden kérést és tárolóbetöltést tilt.
  - Az admin API csak Unix socketen él: `admin unix//run/caddy-admin/admin.sock|0666`, a csak a két konténerbe csatolt `caddy-admin` köteten (könyvtár `root:hatarvedelem 0750`, a portál belépési pontja állítja be). TCP-port és Docker socket nincs.
  - Be→ki váltáskor a portál háttérszála `POST /stop`-ot küld. A Caddy 0-s kóddal kilép, és a `restart: unless-stopped` üres gyorsítótárral visszaindítja; a Docker 26.1.5 `restartmanager` az unless-stopped szabálynál a kilépési kódtól függetlenül újraindít, 100 ms késleltetéssel.
  - A kérés jelzőfájlban (`caddy-restart-pending`) túléli a portál újraindulását. Elérhetetlen Caddynál 2–60 s-os visszalépéssel újrapróbál. Kérésenként egyszer indít újra, ciklusban soha.
  - ACME mellett a tanúsítványfeltöltés is újraindítja a Caddyt, így a feltöltött tanúsítvány megelőzi a memóriában lévő ACME-tanúsítványt.
  - `grace_period 5s`: a leállás legfeljebb 5 s-ig vár a nyitott kapcsolatokra.
  - A Domain beállítások a Caddy állapotát is mutatják: elérhető vagy nem, utolsó újraindítás, folyamatban lévő újraindítás, hiba.
  - A `/data`-hoz semmi nem nyúl.
- **Helyi e2e (Pebble teszt-CA, valódi `caddy:2.10.2-alpine`, podman, `/tmp/acmeoff-e2e/`):**
  1. ACME bekapcsolva: a gyökér és két bejegyzés Pebble-tanúsítványt kapott (3 kiadás); a feltöltött wildcard a `z1` gyökéren, a bejegyzésein és egy ismeretlen aldomainen ment.
  2. A hiba reprodukálva: elrejtett sockettel kikapcsolva az `ask` 404-et adott, a Caddy mégis kiszolgálta a gyorsítótárban lévő Pebble-tanúsítványokat. A státusz ilyenkor: „nem elérhető”, folyamatban.
  3. A socket visszatétele után 3 s-on belül újraindult a Caddy (egyszer). Ettől kezdve az ACME-nevek kézfogása hibás („decision func … 404”), a feltöltött wildcard működik.
  4. Normál úton (elérhető sockettel) a kikapcsolás után 0,2 s-mal már nem ment az ACME-tanúsítvány a gyökéren.
  5. Kézi Caddy-újraindítás után is kikapcsolva maradt.
  6. Visszakapcsolva ugyanazok a sorozatszámok jöttek vissza („loaded certificate from storage”), új kiadás nélkül (Pebble: 3 → 3), és Caddy-újraindítás sem volt.
  7. Feltöltés ACME mellett: a memóriában lévő Pebble-tanúsítvány helyett a feltöltött ment.
  8. A jelzőfájllal újraindított portál egyszer állította le a Caddyt; utána 65 s alatt csak ellenőrzés futott, újabb `/stop` nem.
  9. Leállított portálnál a Caddy fut tovább, de az `ask`/`get_certificate` nem válaszol, így nem szolgál ki semmit (fail-closed, mint eddig).
  10. Változatlanul működik: forward_auth (200 és 401), challenge-oldal (403 + `sus.png`), a `__Host-dropjak_pass` süti levágása, a 80-as átirányítás (308/302), a gyökéren a `/api/proxy/*` 404, a `/api/proxy/cert` a Caddyn át nem kérhető le.
  11. Socket-jogok kötettel: a 999-es csoport elérte, az 1000-es uid `Permission denied`-et kapott. A Caddy (root, `DAC_OVERRIDE` nélkül) létrehozta és újraindításkor újra is létrehozta a socketet.
- **Élesítéskor:**
  - Új `caddy-admin` kötet jön létre.
  - Mindkét konténer újraindul: a compose a módosított konfiguráció miatt a Caddyt is újra létrehozza, és ez egyben üríti a mostani, elavult gyorsítótárat is.

### 3.11.0 – Proxy fül: TCP/UDP port proxy (helyben kész, nincs élesítve)

- **Felhasználói kérés:** a Domainek fülhöz hasonló Proxy fül, ahol reverse proxy állítható be input és forward irányban is. Például a 25565-ös portra érkező forgalom, ha a kliens szabálya engedi, a megadott IP-re (forward) vagy erre a hostra (input) megy. TCP és UDP is kell, a Minecraft Simple Voice Chat (UDP 24454) miatt; socattal működött, rinetd-vel nem (a klasszikus rinetd csak TCP).
- **Döntés: kernelszintű DNAT (nftables), nem userland proxy.** A kliens IP-je megmarad, az UDP a conntrackkel működik, nincs külön folyamat, és a meglévő engedélyhalmazok (`allowed_tcp/udp`, `allowed_input_tcp/udp`) használhatók.
- **Adatmodell:** `port_proxies` lista a `firewall-settings.json`-ban (legfeljebb 64). Mezők: `id`, `label`, `proto` (`tcp`/`udp`/`both`), `listen_port`, `type` (`input`/`forward`), `target_ip` (csak forward, 10/8, 172.16/12, 192.168/16), `target_port`, `ifaces` (`wan`/`lan`/`both`), `snat` (csak forward), `enabled`. A kulcs nélküli régi fájl üres listát ad.
  - Fenntartott hallgató portok: 22, 53, 67, 80, 443, 2019 és a portál portja.
  - A (protokoll, hallgató port) pár egyedi; a `both` a TCP-t és az UDP-t is foglalja, a kikapcsolt bejegyzés is.
  - Input célport nem lehet 22 (az SSH csak explicit TCP 22 host szabállyal nyílhat), 2019 és a portál portja.
  - Input bejegyzésnél a célport nem lehet azonos a hallgató porttal: az ilyen redirect semmit nem csinál, és ugyanezt egy host szabály önmagában megnyitja. Ezért elutasítjuk.
- **nft-láncok** (a portál tölti fel, a sablon-újratöltés nem üríti):
  - `portproxy_prerouting`: saját `type nat hook prerouting priority -101` lánc, csak `jump portproxy_nat`.
  - `portproxy_nat`: forwardnál `dnat ip to <cél>:<port>`, inputnál `redirect to :<port>`. Csak a hostnak címzett forgalomra (`fib daddr type local`), a választott interfészeken; így egy LAN-kliens külső, azonos portú szerverre menő forgalma érintetlen.
  - `portproxy_input`: az input láncból ugrik ide, a fail2ban-drop, a blokk, a MAC-ellenőrzés és a proxy-tiltás után, de a 80/443 proxy-elfogadás, a host-őrök és az established-accept előtt. Engedély: (kliens IP, EREDETI hallgató port) az `allowed_input_*` halmazban (`ct original proto-dst`), mert a redirect után a csomag célportja már a célport. A nem engedélyezett csomag naplózva eldobódik (`reason=portproxy`), csomagonként, ezért a visszavonás a nyitott kapcsolatot is elvágja.
  - `portproxy_snat`: a postrouting első ugrása; csak a kért forward bejegyzés folyamára masquerade.
  - A forwardhoz nem kellett új szabály: a forward lánc meglévő `ct original ip saddr . ct original proto-dst @allowed_tcp/udp` szabálya (FWD_MARK-kal) engedélyezi, ugyanúgy, mint a Docker által publikált portokat.
- **Példa** (Minecraft forward a WAN-ról, Voice Chat input a LAN-ról):

  ```
  add rule inet hatarvedelem portproxy_nat iifname "eth0" fib daddr type local tcp dport 25565 dnat ip to 192.168.10.20:25565
  add rule inet hatarvedelem portproxy_nat iifname "eth1" fib daddr type local udp dport 24455 redirect to :24454
  add rule inet hatarvedelem portproxy_input iifname "eth1" meta l4proto udp ct status dnat ct original proto-dst 24455 ip saddr . ct original proto-dst @allowed_input_udp ip saddr . ether saddr != @client_mac limit rate 30/minute burst 60 packets log prefix "dropjak-drop reason=mac " group 5
  add rule inet hatarvedelem portproxy_input iifname "eth1" meta l4proto udp ct status dnat ct original proto-dst 24455 ip saddr . ct original proto-dst @allowed_input_udp ip saddr . ether saddr != @client_mac drop
  add rule inet hatarvedelem portproxy_input meta l4proto udp ct status dnat ct original proto-dst 24455 ip saddr . ct original proto-dst @allowed_input_udp accept
  add rule inet hatarvedelem portproxy_input meta l4proto udp ct status dnat ct original proto-dst 24455 limit rate 30/minute burst 60 packets log prefix "dropjak-drop reason=portproxy " group 5
  add rule inet hatarvedelem portproxy_input meta l4proto udp ct status dnat ct original proto-dst 24455 drop
  ```
- **Docker DNAT elsőbbsége:** a Docker `ip nat PREROUTING`-ja -100-as prioritású, ugyanannyi, mint a mi `prerouting` láncunké; azonos prioritásnál a sorrend a regisztráció sorrendjétől függ. A kernel (`nf_nat_inet_fn`) a nat láncokat prioritás szerint hívja, és az első NAT-kötés után a többit nem futtatja. A -101-es lánc ezért determinisztikusan nyer: a beállított interfészeken a Proxy bejegyzés megelőzi a Docker azonos portú publikálását. Nem tiltjuk az ilyen portot, csak figyelmeztetünk (a mentés válaszában és a felületen), ugyanígy, ha helyi socket már figyel a porton (`/proc/net/tcp*`, `udp*`, és a `ip nat DOCKER` lánc).
- **Mellékjavítás (a forward lánc MAC-ellenőrzése):** a portos engedélyek LAN-os MAC-ellenőrzése az IP+MAC párt a válaszirányban is vizsgálta. Egy LAN-on lévő DNAT-cél válasza a cél saját IP/MAC párjával érkezik a LAN-interfészen, ezért eldobódott (`reason=mac`). Most csak az eredeti irányt nézi (`ct direction original`).
- **Mentés:** a `_admin_settings_action` `port_proxies` művelete (admin, origin, zár). Az `apply_settings` a pre-auth és blokk láncokkal egy tranzakcióban cseréli a proxy láncokat, utána ír fájlt, hibánál visszaállít. A megváltozott, új vagy törölt hallgató portok conntrack-bejegyzései törlődnek (`conntrack -D -p <proto> --orig-port-dst <port>`). Audit: `admin_portproxy_changed` a bejegyzések összefoglalójával. Induláskor az `_apply_custom_settings` tölti be; hibás beállításfájlnál a proxy láncok üresek (fail-closed).
- **Felület:** Proxy fül a Domainek mellett, bejegyzésenként kétsoros kártya (1. sor: címke, aktív, törlés; 2. sor: protokoll, hallgató port, típus, cél IP, célport, interfész, SNAT). Lenyitható súgó a Minecraft és a Voice Chat példájával (a szerveren `port=24454`, eltérő nyilvános portnál `voice_host=<nyilvános név>:<hallgató port>`). HU/EN/DE.
- **Tesztek:** 721 teszt, mind átment (`tests/test_port_proxy.py`: tárolóellenőrzés, pontos nft-sorok, sablon-sorrend, `unshare -rn nft -c`, alkalmazás/visszaállítás; az admin API tesztjei a `test_gateway.py`-ban).
- **Helyi csomagszintű próba** (user namespace, veth-párok, nem része a tesztkészletnek): forward TCP/UDP engedéllyel átment, a cél a kliens IP-jét látta, a -100-as hamis „Docker” DNAT nem érvényesült; SNAT-tal a cél a router címét látta. Input csak a hallgató portra adott engedéllyel ment át (a célportra adott engedéllyel nem). Engedély nélkül, tiltott IP-ről és visszavonás után eldobódott. Ez a próba hozta elő a fenti MAC-hibát.

## Fontos döntések

- **Cloudflare nem lehet a láncban.** A Dropjak váltja ki a Cloudflare-t a felhasználó stackjében, ezért se Cloudflare API, se Cloudflare-proxy.
- **Ismeretlen aldomain:** HTTPS-en TLS-hiba (nincs wildcard), HTTP-n átirányítás a gyökérre (3.8.1). A challenge-ág a kódban marad, egy feltöltött wildcard tanúsítvánnyal azonnal működik.
- **Wildcard automatizálás később:** a Dropjak saját DNS-szerver lesz a delegált zónára (NS + glue a regisztrátornál), és DNS-01-gyel kér tanúsítványt. Akkor kerül elő, amikor a teljes Cloudflare-kiváltás aktuális lesz.
- **Hozzáférés:** domain-szabály kell, admin- és teljes hozzáférésű kivétel nincs; a publikus bejegyzésekhez nem kell belépés.
- **A `HV_PORTAL_URL` változatlan,** mert a LAN captive portál HTTP-n marad.

## Teszt-infrastruktúra a VM-en

- `/root/nginx-teszt/`: három nginx konténer, csak a 127.0.0.1-en elérhetők.

  | Konténer | Port | Tartalom |
  |---|---|---|
  | teszt1 | 8081 | kék oldal, `/info.html` aloldallal |
  | teszt2 | 8082 | zöld oldal |
  | teszt3 | 8083 | narancs oldal |

- Élő bejegyzések: `teszt1`, `teszt2` és `teszt3` a `z2.moodpatcher.com` alatt.
- Domain-szabály: `teszt-access`, amely tagja az `mpwerks` gyűjtőszabálynak is.

## Mentések és visszaállítás (VM, `/root/hatarvedelem-backups/`)

| Verzió előtt | Mentés | Előző image tag |
|---|---|---|
| 3.4.0 | `hatarvedelem-20261021-165039.tar.gz`, `env-20261021-165049.bak` | `prev-3.3.0` |
| 3.5.0 | `hatarvedelem-20261021-190830.tar.gz` | `prev-3.4.0` |
| 3.6.0 | `hatarvedelem-20261021-195157.tar.gz`, `pre-3.6.0-20261021-195057/` | `prev-3.5.0` |
| 3.7.0 | `hatarvedelem-20261021-210454.tar.gz` | `prev-3.6.0` |
| 3.8.0 | `hatarvedelem-20261021-215908.tar.gz` | `prev-3.7.0` |
| 3.8.1 | `hatarvedelem-20261021-221554.tar.gz` | `prev-3.8.0` |
| 3.9.0 | `hatarvedelem-20261021-223337.tar.gz` | `prev-3.8.1` |
| 3.9.1 | `hatarvedelem-20261021-224148.tar.gz` | `prev-3.9.0` |

**Visszaállítás:**

```sh
docker tag hatarvedelem:prev-X hatarvedelem:2
docker compose up -d --force-recreate
```

Szükség esetén a state archívum visszatöltése is kell.

## Ismert korlátok és kockázatok

- **IP-alapú azonosítás:** az azonos nyilvános IP mögött ülők (NAT, CGNAT) osztoznak a jogosultságon. Javasolt továbblépés: süti alapú azonosítás.
- **Már nyitott kapcsolatok:** a WebSocket- és streaming kapcsolatok a visszavonás után is élnek.
- **Kitett felület:** a Caddy és a portál mindenki számára elérhető támadási felület. A 80/443-as próbálkozásokat a csomagalapú fail2ban nem látja; ezeket a proxy-kategória számolja.
- **Közvetlenül elérhető upstream:** ha egy upstream nem csak a 127.0.0.1-en hallgat, és portszabály megnyitja, a domain-szabály megkerülhető.
- **Forward célpont:** nem tiltja a tűzfal saját LAN-címét.
- **Port proxy forward célja a tűzfal saját címe:** nem tiltjuk; ilyenkor a csomag az input láncba kerül, és csak a célportra adott host engedéllyel menne át. Erre az Input típus való.
- **Port proxy és a drop-alapú fail2ban:** a `reason=portproxy` eldobás számít a tiltásba, mint a `no-grant`; egy belépés nélkül sokat próbálkozó játékkliens így kitiltható.
- **Csak IPv4:** az IPv6 bejövő forgalom eldobódik, ezért AAAA rekord nem lehet.
- **LAN:** belépés előtt a LAN-kliensek nem érik el a 443-at, ezért náluk a HTTP-s captive portál marad.
- **Fail2ban-tiltott IP:** tiltóoldalt csak a :8100-on lát, a HTTPS-portálon nem.
- **Nem böngészős kliensek** (API, webhook, CLI): bekapcsolt challenge-pipák mellett 403-at kapnak.
- **Tanúsítvány-cache (3.10.0 óta kezelve):** az ACME kikapcsolása és az ACME melletti feltöltés újraindítja a Caddyt (legfeljebb néhány másodperc kiesés, a nyitott kapcsolatok megszakadnak). Ha a Caddy épp egy tanúsítványt kér, az újraindítás ezt megszakíthatja, és a következő kézfogás újra kéri (egy elpazarolt kiadás). Restart policy nélkül a Caddy a `/stop` után leállva maradna.

## Teendők

- [x] A 3.8.0 élesítése. Új image: `40a2802222c5`; az előző `hatarvedelem:prev-3.7.0` néven megmaradt. Mentés: `hatarvedelem-20261021-215908.tar.gz`.
- [x] A 3.8.0 ellenőrzése a VM-en: a Caddyfile rendben van, a `.env` nem változott.
- [x] 3.10.0: a kikapcsolt automatikus tanúsítvány javítása és a Pebble-teszt.
- [ ] 3.10.0 élesítése (jóváhagyva; SSH kell).
- [ ] Döntés a VM időzónájáról (`Europe/Budapest`?). A VM `Etc/UTC`, a konténer a gép idejét látja.
- [ ] A 3.9.0 „spam” pipájának és a 3.9.1 képigazításának élő kipróbálása egy pipával ellátott bejegyzésen.
- [ ] 3.11.0 (Proxy fül) élesítése és élő próbája Minecrafttal + Simple Voice Chattel.
- [ ] A 3.7.0–3.9.1 commitolása és pusholása.
- [x] A 3.7.0 `recreate` naplójának ellenőrzése a VM-en.
- [ ] A VM projektmappájából törölhető a nem használt `Unauthorized Wojak Prohibition Emblem.png`.
- [ ] Opcionális: süti alapú proxy-azonosítás, upstream-kötés ellenőrzése, Turnstile élő tesztje.
