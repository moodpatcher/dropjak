# Dropjak / hatarvedelem — projektállapot
**Dokumentum dátuma:** 2026-10-21
**Élő verzió:** 3.3.0 · **Helyi munkakönyvtár:** 3.3.1
**Élő tesztkörnyezet:** 88.198.151.195, portál: <http://88.198.151.195:8100/>
**Projekt gyökere a VM-en:** `/root/hatarvedelem`
**Ez a dokumentum:** helyi, egybefüggő állapotkép; nem telepítési útmutató és nem commit.

## Hogyan olvasd ezt a dokumentumot
Ez a leírás háromféle állapotot különböztet meg, és ezt a szövegben is jelöli:

| Jelölés | Jelentés |
|---|---|
| **ÉLŐ** | A 88.198.151.195 teszt VM-en a 3.3.0-s image fut, és az adott viselkedés a megadott snapshot szerint elérhető. |
| **LOKÁLIS KÓD** | A `/home/moodpatcher/hatarvedelem` munkakönyvtárban lévő forrás írja le; a futó VM-en való megjelenése nem feltétlenül külön ellenőrzött. |
| **TERV / ELHALASZTVA** | Szándék, dokumentum vagy `todo.txt`-elem; nincs implementálva vagy nincs élőben. |
| **NEM ELLENŐRZÖTT** | A rendelkezésre álló fájlokból nem lehet egyértelműen megállapítani; nem állítom biztos tényként. |

A dokumentum nem tartalmaz és nem idéz titkot: nincs `.env`-tartalom, jelszó, jelszó-hash, TOTP-secret vagy -kód, token, süti, recovery code és személyes IP-cím. A VM nyilvános címe és a projektútvonalak szerepelnek, mert azok az üzemeltetéshez szükségesek.

Ahol a szöveg fájlra vagy viselkedésre hivatkozik, a forrás a helyi repository. Ahol élő állapotot ír, az a 2026-10-21-i snapshot ténye. Ahol a kettő eltérhet, külön jelzem.

## 1. Vezetői összefoglaló
A Dropjak (belső néven és a fájlnevekben: **hatarvedelem**) egy Linuxos, captive-portal típusú hálózati belépőkapu. A hálózat alapértelmezésben **zárt**: a kliens csak akkor kap forgalmat, ha a portálon belép, majd második lépésben kiválaszt egy vagy több hozzáférési szabályt és egy egész órákban megadott időtartamot. Az engedély a kliens IPv4-címéhez és MAC-címéhez kötve, kerneloldali nftables-halmazon keresztül valósul meg. Lejárat vagy kijelentkezés esetén a hozzáférés megszűnik.

A rendszer fő jellemzői:

- **Fail-closed forward lánc.** Ha a portál vagy a Docker nem indul el, a továbbított forgalom tiltva marad.
- **Kétfázisú belépés.** A jelszó (és captcha) önmagában nem nyit hálózatot; külön `POST /api/access` kérés és szabályválasztás kell.
- **Dinamikus nftables-halmazok.** Az engedélyek a kernelben járnak le, akkor is, ha a portál leáll.
- **Irány szerinti szabályok.** `forward` (internet, Docker-publikált szolgáltatás) és `input`/host (a portálgépen futó szolgáltatás) szabályok.
- **Többes szabályválasztás.** Egy munkamenet több szabályt is választhat; az unió irányonként számolódik, a TTL a legszigorúbb `max_ttl`-hez igazodik.
- **Részleges visszavonás.** Egy szabály módosításakor csak az érintett választás és annak pontos kernel-elemei tűnnek el.
- **MAC-kötés és anti-spoofing.** A forrás-IP önmagában nem örökölhető.
- **Host SSH csak portálon keresztül.** Egy admin által létrehozott, TCP 22-t kifejezetten tartalmazó host szabály és aktív, engedélyezett munkamenet kell hozzá.
- **fail2ban.** Három, egymástól függetlenül kapcsolható jelzés alapján tilt: sikertelen belépések, eldobott csomagok és különböző célportok. A küszöbök nem lehetnek 0-k.
- **Naplózás.** JSONL auditnapló (esemény, súlyosság, redakció) és NFLOG-alapú drop-napló.
- **TOTP 2FA.** Opcionális, QR-kódos enrollmenttel, recovery code-okkal, memóriabeli ticketekkel.
- **Háromnyelvű portál.** Magyar, angol, német; világos/sötét téma.

Az élő verzió 3.3.0. A 3.3.0-s fail2ban refaktor (a három jelzés teljesen független kapcsolása, a 0 küszöb megszüntetése, a mentett 0 migrálása és a drop-mesterkapcsoló eltávolítása) a VM-en van; az ezt telepítő recreate a dinamikus halmazok ürítése miatt bezárta a host SSH-t. A helyi munkakönyvtár 3.3.1-et tartalmaz (a független ellenőrzés hibajavításai: a közös tiltáshossz helye, az angol/német validációs üzenet, az üres/letiltott mező mentése, az audit bontása és erősebb tesztek), amely még nincs telepítve. A többes kijelölést kézzel, élőben ellenőrizték (`ssh,mpwerks`), az automata `HV_E2E_MULTI` K6 forgatókönyv azonban még nem futott élőben.

## 2. Jelenlegi élő állapot
### 2.1. Környezet
| Tulajdonság | Érték | Állapot |
|---|---|---|
| Hoszt | `88.198.151.195` | ÉLŐ |
| Operációs rendszer | Debian 13 | ÉLŐ (snapshot) |
| Docker Engine | 26.1.5 | ÉLŐ (snapshot) |
| Projektútvonal | `/root/hatarvedelem` | ÉLŐ |
| Állapot | Docker volume (`hatarvedelem-state`) | ÉLŐ |
| Portál | `http://88.198.151.195:8100/` | ÉLŐ, HTTP 200 |
| API | `/api/status` → `ok: true`, `version: 3.3.0` | ÉLŐ |
| Futó image | `sha256:55b1b218d361c7a2451d4d0c0b90a7199dfd189591fff401a65d2ba7be90bc97` | ÉLŐ (snapshot) |
| Előző image | `sha256:f8f1b20a4cfcafb672c7bcbbf9befe0dc8a55294518c8b30cd997efd5f131547` (3.2.0) | Történeti |
| Konténer uptime / konténer ID | nem szerepel a snapshotban | NEM ELLENŐRZÖTT |

A portál a host hálózatában fut (`network_mode: host`), ezért a `8100` port a hoston hallgat, és nincs Docker `ports:` leképezés. A konténer gyökérfájlrendszere csak olvasható; az állapot a külön kötetben van.

### 2.2. Telepítés és visszaállíthatóság
A 3.3.0 telepítése előtt készült mentések:

```text
/root/hatarvedelem-backups/hatarvedelem-20261021-153034.tar.gz
/root/hatarvedelem-backups/hatarvedelem-state-20261021-153034.tar.gz
```

A korábbi, 3.2.0-hoz tartozó mentések történeti adatok:

```text
/root/hatarvedelem-backups/hatarvedelem-20261021-143300.tar.gz
/root/hatarvedelem-backups/hatarvedelem-state-20261021-143300.tar.gz
/root/hatarvedelem-backups/deploy-3.2.0-20261021-144246.sh
/root/hatarvedelem-backups/deploy-3.2.0-20261021-144246.log
```

A deploy szkript és a log a telepítési folyamat reprodukálhatóságát szolgálja. A mentések tartalma fájlszinten nem volt kibontva ebben a munkamenetben: **NEM ELLENŐRZÖTT**, hogy a két archívum pontosan mely állapotfájlokat és milyen időpontból tartalmaz.

Integritási megfigyelés a recreate előtt:

- a `.env` md5-je változatlan (az értéket ez a dokumentum szándékosan nem tartalmazza);
- a VM-en a `.secret` fájl nem létezett.

A `.env` tartalma nem került beolvasásra és nem szerepel ebben a dokumentumban. A fenti integritási megfigyelés csak azt jelzi, hogy a telepítés nem írta át a környezeti fájlt.

### 2.3. Ismert élő viselkedés
- A 3.3.0 telepítése után a **host SSH zárva maradt**. Ennek oka a design: a recreate során a dinamikus nftables-halmazok kiürültek, köztük az `allowed_input_tcp` is, így a korábbi `(IP, 22)` engedély eltűnt. Az újraengedélyezés a portálon történik, ugyanarról a nyilvános IP-ről.
- A portál a böngészőből elérhető, a `/api/status` válasz `ok: true`, a verzió `3.3.0`.
- A többes szabályválasztás élő kézi ellenőrzése megtörtént az `ssh` és `mpwerks` szabályokkal.
- Az automata többes K6 élő futtatása nem történt meg.
- A helyi teljes tesztkészlet a 3.3.1-es munkakönyvtárban **574 teszt OK**, a portál inline JavaScriptjének szintaktikai ellenőrzése OK.

### 2.4. Munkakönyvtár állapota
A snapshot szerinti git állapot nem tiszta: több módosított fájl és több új, még nem követett teszt-/dokumentumfájl van. Ez nem feltétlenül hiba: a 3.3.0-s változtatások egy része a helyi munkakönyvtárban lehet, miközben a futó image már tartalmazza őket; a 3.3.1-es javítások viszont csak helyben vannak. A commit/push állapot és a helyi és élő kód bitre azonos volta **NEM ELLENŐRZÖTT**.

## 3. Architektúra
### 3.1. Futásidejű komponensek
```text
Böngésző (kliens)
    |
    | HTTP :80 / :8100
    v
+----------------------------- host, inet hatarvedelem -----------------------------+
|  nftables: prerouting (redirect), forward (policy drop), input (policy drop)     |
|  dinamikus halmazok: allowed_v4, allowed_tcp, allowed_udp, allowed_input_tcp,     |
|  allowed_input_udp, allowed_icmp, client_mac, banned_v4                           |
|  statikus őrhalmazok: host_service_tcp, host_service_udp                           |
+------------------------------------+-----------------------------------------------+
                                     |
                                     | nft / conntrack / ARP
                                     v
+---------------------------- Docker konténer (host network) -----------------------+
|  docker/entrypoint.sh                                                              |
|    - sablon renderelése és betöltése                                                |
|    - dinamikus halmazok ürítése induláskor                                         |
|    - boot-tábla törlése, Docker DOCKER-USER guard, watchdog                        |
|    - setpriv → hatarvedelem felhasználó                                            |
|  server.py  ── HTTP API, portál, admin, auth, session cookie                       |
|  gateway.py ── szabályok, munkamenetek, nft-hívások, visszavonás, TTL              |
|  fail2ban.py ── login- és drop-alapú tiltás, perzisztencia                         |
|  droplog.py ── NFLOG csoport 5 olvasása, drops.jsonl, rotáció                      |
|  settings_store.py ── pre-auth/block/site beállítások validálása, atomikus írás    |
+------------------------------------------------------------------------------------+
```

A konténer nem a saját hálózati névterében dolgozik: a host `forward` láncát kell elérnie, ezért `network_mode: host`. Emiatt egy hoston csak egy példány futhat, és a portál a host `PORT` portján (alapból `8100`) hallgat.

### 3.2. Felelősségek
| Komponens | Felelősség |
|---|---|
| `server.py` | HTTP szerver, útvonalak, JSON-validáció, origin-ellenőrzés, auth, admin műveletek, statikus `index.html`, `icon.png`, `blocked.png`. |
| `gateway.py` | `Rule`, `RuleSelection`, `Ports`, `Session`, `SessionManager`; az nft-halmazok írása, conntrack törlés, visszavonás, lejárat, induláskori reconciliation. |
| `fail2ban.py` | Sikertelen belépések és drop-események számlálása; `banned_v4` írása; perzisztált `fail2ban.json`; futásidejű konfiguráció. |
| `droplog.py` | NFLOG netlink csoport olvasása, drop rekordok JSONL-be írása, rotáció, szűrés, fail2ban-események összevonása. |
| `settings_store.py` | `firewall-settings.json` validálása és atomikus, hibatűrő írása; pre-auth/block/site mezők. |
| `docker/entrypoint.sh` | Első indítási sorrend, env-validáció, nft betöltés, dinamikus halmazok ürítése, Docker guard, watchdog, jogosultságcsökkentés. |
| `install.sh` | Natív, systemd-alapú telepítés; fájlok másolása, helyőrzők kitöltése, unitok és drop-in. |
| `deploy/hv` | Docker-es operatív segédeszköz (status, logs, restart, rebuild, backup, test, e2e). |
| `index.html` | Teljes egyoldalas portál és admin UI, három nyelven. |

### 3.3. Indítási sorrend
1. A hoston a `docker/setup-host.sh` által telepített `hatarvedelem-boot.service` korán betölt egy külön `inet hatarvedelem_boot` táblát: `forward` policy drop, és a host SSH (`tcp dport 22`) tiltása a végleges szabályok betöltéséig.
2. A Docker daemon elindul, majd a konténer.
3. Az `entrypoint.sh` ellenőrzi a kötelező env-értékeket (`HV_LAN_IF`, `HV_WAN_IF`, `HV_LAN_NET`, `HV_PORTAL_NET`), rendereli a sablont, és betölti az `inet hatarvedelem` táblát.
4. Az entrypoint kiüríti a dinamikus halmazokat, hogy ne maradjon munkamenet nélküli engedély. A `host_service_tcp` / `host_service_udp` szándékosan nem ürül.
5. Törli a korábbi `host_ssh_v4` halmazt, ha még létezik; ez már nem adhat hozzáférést.
6. Törli a korai boot-táblát.
7. Ellenőrzi és szükség esetén telepíti a Docker `DOCKER-USER` guardot.
8. Elindítja a watchdogot, majd `setpriv`-vel a `hatarvedelem` felhasználóra vált, és futtatja a `server.py`-t.
9. A `server.py` induláskor betölti a szabályokat, felhasználókat, csoportokat, beállításokat, fail2ban-állapotot, és ha kell, reconcile-olja a kernel halmazokat az üres munkamenet-táblához.

A `HV_SKIP_FIREWALL=1` az nft-betöltést, a Docker guardot és a watchdogot kihagyja. Ez **nem biztonságos**, csak fejlesztői vagy vészhelyzeti opt-in.

## 4. Hálózati és tűzfalmodell
### 4.1. Táblák és láncok
| Objektum | Típus | Szerep |
|---|---|---|
| `inet hatarvedelem` | table | A végleges szabályok. |
| `forward` | filter, priority `-10`, policy `drop` | Minden továbbított forgalom alapból tiltva; a Docker FORWARD lánca előtt fut. |
| `input` | filter, policy `drop` | A host felé menő forgalom; portál, DHCP/DNS, host szabályok. |
| `prerouting` | nat, priority `dstnat` | HTTP → portál redirect, pre-auth/block NAT kivételek. |
| `postrouting` | nat, priority `srcnat` | NAT-kiegészítések. |
| `preauth` | custom | Belépés előtt elérhető célok/portok. |
| `block` | custom | Mindig tiltott célok/portok; minden engedély előtt fut. |
| `preauth_nat` | custom | A pre-auth TCP 80 kikerüli a portál-redirectet. |
| `block_nat` | custom | A blokkolt TCP 80-at már a redirect előtt eldobja. |
| `breakglass` | custom | Vészhelyzeti SSH-szabály; a sablon nem üríti, alapból üres. |
| `inet hatarvedelem_boot` | table | Korai boot-védelem a Docker indulása előtt; a konténer törli. |

A sablon idempotens: a láncok flush-elése és újrafelépítése egy nft-tranzakcióban történik, a dinamikus halmazokhoz pedig nem nyúl. Így az `nft -f` újratöltés nem jelentkezteti ki a klienseket, viszont a konténer indulásakor az entrypoint külön, tudatosan üríti a dinamikus halmazokat.

### 4.2. Dinamikus halmazok
| Halmaz | Kulcs | Méret | Szerep |
|---|---|---|---|
| `allowed_v4` | `ipv4_addr` | 4096 | Teljes hozzáférésű kliens IP-k. |
| `allowed_tcp` | `ipv4_addr . inet_service` | 16384 | Forward TCP célportok kliensenként. |
| `allowed_udp` | `ipv4_addr . inet_service` | 16384 | Forward UDP célportok kliensenként. |
| `allowed_input_tcp` | `ipv4_addr . inet_service` | 16384 | Host TCP portok kliensenként; itt él a `(IP, 22)` SSH-engedély is. |
| `allowed_input_udp` | `ipv4_addr . inet_service` | 16384 | Host UDP portok kliensenként. |
| `allowed_icmp` | `ipv4_addr` | 4096 | ICMP echo engedély. |
| `client_mac` | `ipv4_addr . ether_addr` | 4096 | Az engedélyezett IP-hez rögzített MAC. |
| `banned_v4` | `ipv4_addr` | 4096 | fail2ban által tiltott források. |
| `host_service_tcp` | `inet_service` | 65536 | Csak hozzáadás: minden valaha deklarált host TCP-port. |
| `host_service_udp` | `inet_service` | 65536 | Ugyanaz UDP-re. |

A dinamikus halmazok `timeout` flaggel rendelkeznek; az elemek a munkamenet TTL-jével járnak le a kernelben. A `host_service_*` halmazok szándékosan állandóak és csak bővülnek: a feladatuk, hogy egy visszavont host-hozzáférés established kapcsolatát akkor is elvágják, ha a conntrack ürítése nem sikerül, vagy a kernel újraéleszti a folyamot.

### 4.3. Forgalmi döntések sorrendje
A forward lánc közelítő sorrendje:

1. IPv6 drop (az IPv4 forwarding ellenére is zár).
2. Forrás-IP spoofing tiltása: LAN interfészen csak `HV_LAN_NET`, WAN felől tilos a LAN-forrás.
3. `banned_v4` drop, naplózottan; ez minden engedély és pre-auth előtt fut.
4. MAC-ellenőrzés az engedélyezett IP-khez a LAN-on.
5. `block` lánc; a blokk minden grantet megelőz.
6. Teljes hozzáférés (`allowed_v4`) és portengedélyek (`allowed_tcp`, `allowed_udp`, `allowed_icmp`), `meta mark set 0x44524a4b` jelöléssel.
7. A teljes hozzáférés és az ICMP válasziránya a jelöléssel; a portos engedélyek válaszát a `ct original` szerinti egyezés fedi.
8. Docker konténer kivételei (a sablonban `172.30.0.2`): anti-spoof és LAN-pivot tiltás, DNS és 53/80/443 egress, valamint a konténer által indított kapcsolatok válaszai.
9. `preauth` lánc; a pre-auth a portál megkerülését jelenti, és a válaszirányt is lefedi.
10. Minden más drop.

Az input lánc hasonlóan fail-closed, de a portál, a DHCP és a LAN DNS kivételével. A host SSH-t a `(IP, 22) ∈ allowed_input_tcp` pár nyitja; a generikus established-szabály nem tartja életben a visszavont SSH-t.

### 4.4. Portál és captive portal
A nem engedélyezett kliens HTTP-forgalmát a prerouting lánc a portálra irányítja. A portál mindig elérhető a LAN felől; a WAN felőli elérés a `HV_PORTAL_NET` értékétől függ. A `block` és `preauth` szabályok a pre-DNAT (eredeti) célt nézik, ezért Docker-publikált szolgáltatásnál a VM nyilvános címét és a publikált host portot kell használni, nem a konténer belső címét.

### 4.5. Docker-integráció
A forward szabályok `meta mark set __FWD_MARK__` jelölést tesznek a továbbított csomagokra. A `DOCKER-USER` láncba telepített guard csak a jelölt csomagokat engedi át, minden mást eldob. Ha az `inet hatarvedelem` tábla eltűnik, a Docker nem tud bypass-t nyitni. A mark alapértéke `0x44524a4b`, a drop-log NFLOG csoport alapértéke `5`; ezeknek a portál, az nft-sablon és a drop-log listener között egyezniük kell.

## 5. Biztonsági invariánsok
Ezek a rendszer azon tulajdonságai, amelyeket a kódnak és a teszteknek védeniük kell. A részletes mutációs mátrix a `docs/propagation-matrix.md` fájlban van.

### 5.1. Hozzáférés
1. **Alapból minden tiltva.** A forward és az input lánc is `policy drop`.
2. **Jelszó nem elég.** Sikeres jelszavas (és TOTP) belépés után külön szabályválasztás és `POST /api/access` kell.
3. **Minden engedély IP-hez és TTL-hez kötött.** A kernel timeoutja akkor is lejár, ha a portál nem fut.
4. **MAC-kötés a LAN-on.** Ha az ARP-ből nem oldható fel a MAC, a hozzáférés megtagadva; hibás `client_mac` lista esetén sem lehet MAC nélkül engedélyezni.
5. **Host SSH csak explicit szabállyal.** Csak olyan input szabály nyithatja meg a TCP 22-t, amely kifejezetten felsorolja a 22-t; teljes hozzáférésű szabály soha nem nyit SSH-t.
6. **A portál portja (8100) fenntartott.** A host szabályok validációja nem engedi felvenni; a portál saját, előbb futó elfogadó szabálya kezeli.
7. **A block mindent megelőz.** A block lánc a grantek és a pre-auth előtt fut, ezért egy aktív kapcsolat sem kerülheti meg; a block eltávolítása nem igényel újraengedélyezést.
8. **A fail2ban mindent felülír.** A tiltott forrás csomagjai a forward és input láncban is eldobódnak; csak a portál és a DHCP marad elérhető.
9. **A pre-auth szándékosan nyilvános.** Minden LAN-kliens elérheti a pre-auth célokat belépés nélkül; a listát minimálisan kell tartani.
10. **A breakglass csak vészhelyzeti.** A lánc nem ürül újratöltéskor; használat után azonnal törölni kell a szabályt.

### 5.2. Visszavonás és konzisztencia
1. **A visszavonás tartós.** Sikertelen `nft` hívás esetén pending-revocation bejegyzés marad, amely backoffal újrapróbálódik; a részleges visszavonás csak azt törli, amire már nincs szükség.
2. **Nincs árva grant induláskor.** `HV_FLUSH_ON_START=1` esetén a dinamikus halmazok ürülnek; ha a flush ki van kapcsolva, a portál az üres munkamenet-táblához reconcile-ol, kivéve a kifejezetten nem biztonságos `HV_ALLOW_STALE_GRANTS_ON_START=1` esetet.
3. **A `host_service_*` nem ürül.** Ezek az established host-kapcsolatok védőhálói.
4. **A zárolás és a visszavonás egy lock alatt történik.** `logout`, `terminate`, `revoke_user`, `revoke_rule`, expiry reaper: a munkamenet eltávolítása és a firewall-visszavonás ugyanabban a `SessionManager._lock`-ban fut, hogy egy párhuzamos engedélyezés ne veszítse el a friss grantját.
5. **Többes választásnál irányonkénti unió.** A `full` ugyanabban az irányban elnyeli a TCP/UDP/ICMP-t; az átfedő port csak egyszer kerül a halmazba.
6. **Részleges visszavonás pontos.** A távozó elemeket a rendszer kivonja; a `_subtract_grants` akkor hagyja ki a távozó `full`-t, ha egy aktív, azonos irányú `full` lefedi, és a nem teljes távozó részeket pontos törlésre adja vissza.
7. **Lejárt munkamenetet nem lehet újraengedélyezni.** Részleges visszavonásnál a lejárt munkamenet teljesen eltávolítódik.
8. **Conntrack flush korlátozott.** `CONNTRACK_REMOVED_LIMIT = 16`: ha több célzott törlés kellene, és még marad grant, a rendszer inkább kihagyja a tisztítást, nem flushol IP-szinten.
9. **Hiba esetén fail-closed.** Bármely firewall-hiba a munkamenet eldobásához és a régi unió visszavonásához vezet; HTTP 503.
10. **Minden kiválasztott szabály-ID feloldódik az engedélyezés előtt.** Így egy sikertelen lookup nem hagy részleges grantet.

### 5.3. Admin és auth
- Az admin végpontok `_admin_guard`-dal védettek; a POST kérések JSON-onlyak és same-origin ellenőrzöttek.
- A kliens IP-jét a szerver a socket peer-ből veszi, nem a `X-Forwarded-For` fejlécből.
- Az utolsó aktív admin védelme: nem lehet az utolsó admint törölni/letiltani.
- A felhasználó törlése a csoporttagságot is eltávolítja.
- Az admin user update visszaállítja a korábbi jelszó-hash-t, ha a későbbi metadata- vagy tagságírás meghiúsul.
- A TOTP-ticketek memóriabeliek, 300 másodpercig élnek, IP-hez kötöttek, egyszer használatosak, legfeljebb 5 kísérletet engednek.
- Az auditnapló redaktálja a jelszót, hasht, secretet, TOTP-kódot, recovery code-ot, sütit, tokent, ticketet és `otpauth://` URI-t; e-mail cím nem kerül a naplóba.

### 5.4. Ismert korlátok
Ezek nem nyitott bugok, hanem tudatosan dokumentált maradék kockázatok:

| Korlát | Hatás |
|---|---|
| A `SessionManager` egy globális lockot használ | Nagy terhelésnél a session-műveletek sorosodnak. |
| Leállítás alatt a visszavonás részleges lehet | A hátralévő elemek a kernel TTL-jükig élhetnek; a `host_service_*` és a boot-guard csökkenti a kitettséget. |
| `mixed` irány csak megjelenítési/audit érték | A tényleges műveletek irányonként külön `Ports` részekkel dolgoznak. |
| TOCTOU a MAC-feloldás és a grant között | Elméleti versenyhelyzet; a MAC-kötés nem hitelesítés. |
| A tesztkörnyezet fallbackjei | Bizonyos tesztek mockolt nft-t használnak; a valós kernel-viselkedés külön élő tesztet igényel. |
| Runtime feltételezések | Az nft/conntrack/NFLOG viselkedését a dokumentáció és a tesztek modellezik, de nem minden élő kombinációban ellenőrzött. |

## 6. Adatmodell
### 6.1. Állapotfájlok
A Docker-es telepítésben a `hatarvedelem-state` kötet a `/var/lib/hatarvedelem` helyen jelenik meg. A natív telepítésben ugyanez a `StateDirectory`.

| Fájl | Tartalom | Formátum / mód |
|---|---|---|
| `users.json` | Felhasználók, szerepkör, jelszó-record, TOTP-állapot, szabály-hozzárendelés. | JSON, `0600`, atomikus írás. |
| `groups.json` | Csoportok, tagok, szabály-hozzárendelés. | JSON, `0600`. |
| `rules.json` | Egyedi szabályok és gyűjtőszabályok. | JSON, `0600`; a hibás bejegyzéseket betöltéskor naplózza és kihagyja. |
| `firewall-settings.json` | `site_name`, `registration_enabled`, `preauth`, `block`. | JSON, `0600`; validálás után atomikus csere. |
| `fail2ban.json` | Aktív tiltások, számlálók, konfiguráció. | JSON, `0600`; induláskor visszatöltődik. |
| `audit.jsonl` | Biztonsági auditnapló, új sor = egy JSON objektum. | JSONL, `0600`, fsync; méretalapú rotáció. |
| `drops.jsonl` | NFLOG drop rekordok. | JSONL, rotáció 10 MiB / 5 fájl. |
| `rules.json.admin-full-backup-<timestamp>` | Régi, fenntartott azonosító eltávolításakor készült biztonsági mentés. | `0600`, csak migrációkor. |

A munkamenetek **nem** perzisztálódnak: a `SessionManager` memóriabeli. Ezért minden konténer-újraindítás után újra kell jelentkezni és engedélyezni kell.

### 6.2. Felhasználó
A felhasználói rekord fő mezői (a teljes belső séma a `server.py`-ban van):

| Mező | Jelentés |
|---|---|
| `user` / név | Egyedi login név. |
| `role` | `admin` vagy `user`. |
| `enabled` | Letiltott felhasználó nem léphet be. |
| `pending` | Nyilvános fiókkérelemből jött, még nem jóváhagyott. Hiányzó érték `false`; hibás érték `true` (fail-closed). |
| `email` | Kontaktcím a fiókkérelemből; nem hitelesítő tényező, nem kerül a naplóba. |
| `rules` | Közvetlenül hozzárendelt szabály-ID-k. |
| `groups` | Csoporttagságok. |
| `totp_required` | Kötelező-e a 2FA. |
| `must_change_password` | Első belépésnél jelszócsere kötelező. |
| jelszó-record | PBKDF2-HMAC-SHA256, felhasználónkénti salt, iterációszám, hash; plaintext soha. |
| TOTP-mezők | Secret, utolsó használt step, recovery-code hashek. |

A jelszó nem egyszerű hash: a rendszer a PBKDF2-HMAC-SHA256 rekordot használja, és a `HV_PBKDF2_ITERATIONS` alapértéke `600000`.

### 6.3. Szabály
Egyedi szabály tárolt mezői:

```json
{
  "label": "Csak web",
  "description": "",
  "tcp": [80, 443],
  "udp": [443],
  "icmp": false,
  "full": false,
  "direction": "forward",
  "default_ttl": 3600,
  "max_ttl": 86400,
  "created": 1792500000
}
```

- A `direction` hiányzó értéke betöltéskor `forward`.
- A `full` szabály minden portot és protokollt engedélyez a saját irányában; forward irányban ez internetet jelent, host irányban a validáció tiltja.
- A host (`input`) szabály csak explicit TCP/UDP portokat fogad el; `full`, ICMP és a régi szolgáltatáslista nem megengedett.
- A 8100 fenntartott; a 22 csak külön, explicit host szabályban nyitható.

Gyűjtőszabály tárolt mezői:

```json
{
  "label": "Web + DNS",
  "description": "Két egyedi szabály együtt",
  "members": ["web-only", "dns-only"],
  "default_ttl": 3600,
  "max_ttl": 86400,
  "created": 1792500000
}
```

A gyűjtőnek nincs saját `tcp`, `udp`, `icmp`, `full` vagy `direction` mezője: a portok és az irány a tagokból számított értékek. Ez megakadályozza, hogy egy tag későbbi módosítása elavult uniót hagyjon hátra. A gyűjtés egy szintű, 1–64 taggal; gyűjtő nem tartalmazhat gyűjtőt, önmagát, a fenntartott `admin-full` azonosítót vagy teljes hozzáférésű tagot.

### 6.4. Csoport
A csoport a felhasználók és a szabályok közötti közvetítő. Egy felhasználó effektív szabályai a közvetlen `rules` és a csoportokon keresztül örökölt szabályok uniója. A csoporttagság törlése a felhasználó törlésekor is megtörténik. A részletes csoport-séma a `server.py` és a vonatkozó tesztek szerint működik; a mezőnevek teljes listája itt nem szerepel, mert a dokumentum nem akar belső implementációs részleteket kitalálni.

### 6.5. Beállítások
A `firewall-settings.json` validált mezői:

| Mező | Típus | Alapértelmezés | Megjegyzés |
|---|---|---|---|
| `site_name` | string, max 64 | üres → `Dropjak` | Portálfejléc, böngészőcím, új TOTP-enrollment issuer. |
| `registration_enabled` | boolean | `false` | Nyilvános fiókkérelem kapcsoló. |
| `preauth` | lista | üres | Belépés előtti célok/portok; fail-closed fallback hiba esetén. |
| `block` | lista | üres | Mindig tiltott célok/portok; hiba esetén az utolsó jó állapot marad. |

A `settings_store.py` korlátai: legfeljebb 64 bejegyzés, 64 port, 64 karakteres label, 64 karakteres site name; a szabály-azonosítókra szigorú regex van.

### 6.6. Audit és drop log
Az auditbejegyzés közös mezői: `ts`, `time`, `event`, `severity`, `ip`, `user`, `ua`. A `severity` értéke `info`, `warn` vagy `alert`; a régi bejegyzések `info`-nak számítanak. Az eseménycsaládok: authentication, access, session, admin, fail2ban, service/firewall, CLI, TOTP-ticket lifecycle.

A drop log NFLOG csoport 5-ből érkezik, és csak csomagfejlécet tárol, payloadot nem. A `fail2ban` által okozott dropokat a portál egyetlen ban-eseménnyé vonja össze, így a felület egy sorban mutatja a tiltást és a „fail2ban utáni kísérlet” összegzést.

## 7. Portál UI
A portál egyetlen `index.html`, beágyazott CSS-sel és JavaScripttel. Három nyelv: magyar (`hu`, alapértelmezett), angol (`en`), német (`de`). A témát a rendszer beállítása követi, de a jobb alsó sarokban kézzel is váltható; a választás `localStorage`-ban marad.

### 7.1. Kliensoldali képernyők
| Képernyő | Funkció |
|---|---|
| Belépés | Felhasználónév, jelszó, captcha (helyi proof-of-work vagy Cloudflare Turnstile). |
| TOTP | 6 jegyű kód vagy recovery code; tickethez kötött, IP-ellenőrzött. |
| TOTP enrollment | Böngészőben generált QR (Nayuki qrcodegen inline), base32 secret és `otpauth://` URI manuális fallbackkel. |
| Recovery code-ok | Első sikeres enrollment után egyszer mutatja a 10 kódot. |
| Tiltás | Aktív fail2ban-ban a belépő helyett tiltóképernyő visszaszámlálóval. |
| Szabályválasztás | Több kártya jelölhető; a TTL egész órákban, a legszigorúbb `max_ttl` a felső korlát. |
| Munkamenet | Aktív hozzáférések, lejárat, módosítás, kijelentkezés. |
| Jelszócsere | Külön végpont; érvényes munkamenetet kér. |

### 7.2. Többes kijelölés és élő frissítés
A 3.2.0-ban a jogosult portál 30 másodpercenként pollozza a `/api/status`-zt, és frissíti a szabálykatalógust. A módosítás képernyő nem dobja ki a felhasználót: a még érvényes kijelölések megmaradnak, a szerver által visszavont választás eltűnik, és a felület jelzi, hogy az érintett hozzáférést újra kell engedélyezni. A TTL-hint minden kiválasztott szabályt felsorol, megjelöli a felső korlátot adó szabályt, és a tooltipben a teljes listát mutatja.

### 7.3. Admin felület
Az admin oldal fülei:

| Fül | Funkció |
|---|---|
| Users | Felhasználók létrehozása, szerkesztése, törlése, szerepkör, szabályok, csoportok, TOTP reset, pending fiókkérelmek jóváhagyása/elutasítása. Utolsó admin védelme. |
| Groups | Csoportok és tagságok, szabály-hozzárendelés. |
| Rules | Egyedi szabályok, gyűjtőszabályok, duplikálás, jelszógenerátor, irány, TTL-ek, portok. |
| Sessions | Aktív munkamenetek, kényszerített lezárás, választott szabályok. |
| Firewall | Per-IP áttekintés, kernel grantek, munkamenetek; Raw rules nézet (`iptables -L -n` stílus), a pre-auth/block láncokkal. |
| Drop log | Dropok forrás/cél szerint, protokoll/port/szöveg szűrők, grafikon, fail2ban-események összevonva. |
| Fail2ban | Státusz, aktív tiltások visszaszámlálóval, várakozó kísérletek, kézi ban/unban, login- és drop-küszöbök, külön drop-metrika kapcsolók. |
| Logs | Auditnapló szűrők: esemény, felhasználó, szöveg, súlyosság, darabszám. Eseményválasztó ismert kódokból. A `before` kurzor csak API-szinten érhető el. |
| Settings | Tűzfalnév, fiókkérelmek, pre-auth, block; validálás, nft-alkalmazás, atomikus mentés. |

A **Rules** fülön a jelszógenerátor kliensoldali; a **Duplikálás** az `action: "duplicate"` API-t hívja. A **Settings** változtatásai előbb az nftables-re mennek, és csak siker esetén íródnak a fájlba; hiba esetén a korábbi láncok állnak vissza.

### 7.4. Fiókkérelmek
A `registration_enabled` alapból `false`. Bekapcsolva a belépőoldalon megjelenik a **Fiók kérése** gomb. A kérelem jelszót, jelszó-megerősítést (csak UI) és e-mail-címet kér, a szokásos captchával. A létrejövő fiók `pending=true`, `enabled=false`, `rules=[]`, `totp_required=false`, `must_change_password=false`, szerepe `user`; nem kap sütit és nem tud belépni. Az admin a Users fülön jóváhagyja vagy elutasítja. A jóváhagyás nem ad szabályt és nem ad hozzáférést.

A regisztráció JSON-only, same-origin, IPv4-only, dedikált rate limittel (3 kérés / 10 perc / forrás-IP). Az e-mail cím tárolva van, de nem kerül kiküldésre, nem hitelesített és nem használható jelszó-visszaállításra.

## 8. API felületek
Az alábbi lista a `server.py` dispatch-táblájából származik. A POST végpontok JSON testet várnak; a szerver a `Content-Type`-ot és az `Origin` fejlécet ellenőrzi, ahol releváns. A hibák jellemzően `{"ok": false, "error": "...", "code": "..."}` alakúak.

### 8.1. Nyilvános és munkamenet-végpontok
| Metódus | Útvonal | Cél | Auth |
|---|---|---|---|
| GET | `/api/challenge` | Proof-of-work captcha kihívás. | nem |
| GET | `/api/status` | Verzió, `registration_enabled`, a munkamenet állapota, szabályok, grantek. | nem / süti szerint |
| POST | `/api/register` | Nyilvános fiókkérelem; pending fiók. | nem |
| POST | `/api/login` | Jelszavas belépés, captcha; TOTP esetén ticket. | nem |
| POST | `/api/login/totp` | TOTP-kód ellenőrzése, munkamenet létrehozása. | ticket |
| POST | `/api/login/totp/enroll` | Enrollment megerősítése, recovery code-ok. | ticket |
| POST | `/api/login/recovery` | Recovery code használata. | ticket |
| POST | `/api/access` | Szabály(ok) és TTL engedélyezése; többes payload: `{"rules": [...], "rule": first, "ttl": N}`. | munkamenet |
| POST | `/api/logout` | Kijelentkezés, grant visszavonása. | munkamenet |
| POST | `/api/password` | Jelszócsere. | munkamenet |

A `/api/status` válasza a jogosult munkamenetnek tartalmazza a `selected_rules`, `selected_rule_labels` és irányonkénti `grants` mezőket is; a régi `rule`, `rule_label`, `grant` mezők kompatibilitási okból megmaradnak. A `MAX_SESSION_RULES = 16`.

### 8.2. Admin GET végpontok
| Útvonal | Tartalom |
|---|---|
| `/api/admin/state` | Teljes admin állapot: felhasználók, csoportok, szabályok, beállítások, verzió. |
| `/api/admin/logs` | Auditnapló; `limit`, `event`, `user`, `q`, `before`, `severity`. |
| `/api/admin/sessions` | Aktív munkamenetek. |
| `/api/admin/firewall` | Per-IP kernel grantek és munkamenetek. |
| `/api/admin/firewall-rules` | Nyers nft szabálylista. |
| `/api/admin/drops` | Drop log, szűrőkkel. |
| `/api/admin/settings` | Pre-auth/block/site beállítások. |
| `/api/admin/fail2ban` | fail2ban státusz, tiltások, várakozó kísérletek. |

### 8.3. Admin POST végpontok
| Útvonal | Műveletek |
|---|---|
| `/api/admin/users` | create, update, delete, approve, reject, totp reset, szerepkör/tagság kezelés. |
| `/api/admin/groups` | create, update, delete, tag-hozzárendelés. |
| `/api/admin/rules` | create, update, delete, duplicate; egyedi és gyűjtő szabály. |
| `/api/admin/sessions` | terminate. |
| `/api/admin/settings` | pre-auth/block módosítás, `site_name`, `registration_enabled`. |
| `/api/admin/fail2ban` | configure, ban, unban, unban-all. |

Az admin műveletek naplózódnak (`admin_*` események), a tiltott kérés `admin_denied` / `admin_request_rejected`, a végrehajtási hiba `admin_action_failed`.

### 8.4. Statikus erőforrások
| Útvonal | Tartalom |
|---|---|
| `/` | `index.html`. |
| `/icon.png`, `/favicon.ico` | Ikon. |
| `/blocked.png` | Tiltóképernyő képe. |

A portál `server_version` értéke `Hatarvedelem/2`; ez nem azonos a termékverzióval. A termékverziót a `VERSION` fájl és a `/api/status` `version` mezője adja.

## 9. Konfiguráció
### 9.1. Kötelező környezeti változók
A Docker-es entrypoint ezeket kötelezőnek tekinti; hiányukban a konténer nem indul el (fail-closed):

| Változó | Példa | Jelentés |
|---|---|---|
| `HV_LAN_IF` | `eth1` | Kliensoldali interfész. |
| `HV_WAN_IF` | `eth0` | Internet felé menő interfész. |
| `HV_LAN_NET` | `192.168.10.0/24` | Klienshálózat IPv4 CIDR-ben. |
| `HV_PORTAL_NET` | `0.0.0.0/0` | Honnan érhető el a portál; üresen `HV_MGMT_NET`. |

A `HV_LAN_IF` és `HV_WAN_IF` nem lehet ugyanaz. A portál a LAN felől mindig elérhető; a `HV_PORTAL_NET=0.0.0.0/0` a WAN felé is kiteszi, ezért csak indokolt esetben használható.

### 9.2. Fő beállítások
| Változó | Alapértelmezés | Szerep |
|---|---|---|
| `PORT` | `8100` | Portál port a hoston. |
| `HV_PORTAL_URL` | üres | Kanonikus portálcím. |
| `HV_SESSION_TTL` | `3600` | Alapértelmezett hozzáférési idő másodpercben. |
| `HV_MIN_TTL` / `HV_MAX_TTL` | `60` / `2592000` | Globális TTL-korlát; a szabály `max_ttl` ezen felül szűkít. |
| `HV_AUTH_TTL` | `600` | Jelszavas belépés és szabályválasztás között; 60–3600 közé szorítva. |
| `HV_POW_DIFFICULTY` | `4` | Proof-of-work nehézség (1–6 vezető hex nulla). |
| `HV_CHALLENGE_TTL` | `600` | Captcha-kihívás élettartama. |
| `HV_PBKDF2_ITERATIONS` | `600000` | Jelszó-hash iterációszám. |
| `HV_RATE_WINDOW` / `HV_RATE_MAX` | `60` / `10` | Login rate limit. |
| `HV_TOTP_ISSUER` | `Dropjak` | TOTP issuer fallback, ha nincs site name. |
| `HV_COOKIE_SECURE` | `0` | `1` HTTPS-terminálás mögött. |

### 9.3. Tűzfal, állapot, fail2ban
| Változó | Alapértelmezés | Szerep |
|---|---|---|
| `HV_FWD_MARK` | `0x44524a4b` | Forward mark; a Docker guard ehhez igazodik. |
| `HV_DROP_LOG_GROUP` | `5` | NFLOG csoport. |
| `HV_NFT_TABLE` / `HV_NFT_SET` | `hatarvedelem` / `allowed_v4` | nft tábla és teljes hozzáférésű halmaz. |
| `HV_FLUSH_ON_START` | `1` | Induláskori dinamikushalmaz-ürítés. |
| `HV_ALLOW_STALE_GRANTS_ON_START` | `0` | `1` esetén a régi grantek munkamenet nélkül is életben maradhatnak; **nem biztonságos**. |
| `HV_FIREWALL_WATCHDOG` | `1` | Tűzfal-figyelő. |
| `HV_DRY_RUN` / `HV_SKIP_FIREWALL` / `HV_RUN_AS_ROOT` | `0` | Nem ír nft-t / kihagyja a betöltést / root futtatás. Az utóbbi kettő **nem biztonságos**. |
| `HV_FAIL2BAN` | `1` | Login-alapú tiltás kapcsolója (0: csak a belépés-figyelés ki). |
| `HV_FAIL2BAN_MAX` | `5` | Sikertelen belépés a tiltásig (1–100). |
| `HV_FAIL2BAN_WINDOW` / `HV_FAIL2BAN_BAN` | `600` / `3600` | Időablak és tiltás hossza. |
| `HV_FAIL2BAN_DROP` | `1` | Első indulásnál mindkét drop-mérőszámot kapuzza; futásidőben külön kapcsolhatók. |
| `HV_FAIL2BAN_DROP_COUNT_ENABLED` / `HV_FAIL2BAN_DROP_PORTS_ENABLED` | `1` | A két drop-metrika első indulású alapértéke. |
| `HV_FAIL2BAN_DROP_MAX` / `HV_FAIL2BAN_DROP_PORTS` | `120` / `12` | Csomag- és portküszöb (1–10000 / 1–4096); a 0 érvénytelen, alapértékre esik vissza. |
| `HV_FAIL2BAN_DROP_WINDOW` | `180` | Drop időablak (30–86400). |
| `HV_ADMIN_ENABLED`, `HV_ADMIN_USER`, `HV_ADMIN_PASSWORD`, `HV_ADMIN_PASSWORD_FILE` | `0` / üres | Induláskori admin fiók létrehozása/frissítése; fájl is adható. |
| `TURNSTILE_SITEKEY`, `TURNSTILE_SECRET` | üres | Opcionális Cloudflare Turnstile; enélkül helyi proof-of-work. |
| `HV_CONNTRACK_BIN` | auto | Egyedi `conntrack` binary. |

A futásidejű fail2ban-értékek az admin **Fail2ban** fülön állíthatók; a környezeti változók csak az első indulás alapértékei. A belépés-figyelés kikapcsolása csak a belépéses, a két drop-mérőszám együttes kikapcsolása csak a drop-os automatikus tiltásokat oldja fel; a kézi tiltások megmaradnak.

### 9.4. Állapot- és naplóútvonalak
Az alapértelmezett gyökér `HV_STATE_DIR=/var/lib/hatarvedelem`; innen `users.json`, `rules.json`, `groups.json`, `firewall-settings.json` (`HV_SETTINGS`), `audit.jsonl` (`HV_AUDIT_LOG`), `drops.jsonl` (`HV_DROP_LOG_PATH`), `fail2ban.json` (`HV_FAIL2BAN_STATE`). A rotáció: audit és drop log `10 MiB`, 5 fájl. A szolgáltatáskatalógus `HV_SERVICES_FILE=/opt/hatarvedelem/services.json`.

### 9.5. nft helyőrzők
A sablon hét helyőrzőt tartalmaz, amelyeket az entrypoint és az `install.sh` is kitölt:

```text
__LAN_IF__  __WAN_IF__  __LAN_NET__  __PORTAL_NET__
__PORT__  __FWD_MARK__  __DROP_LOG_GROUP__
```

A renderelés után a fájlban nem maradhat `__...__` minta; az `install.sh` és a natív unitok ezt ellenőrzik.

### 9.6. Helyi fejlesztői szabály
A helyi fejlesztői gépen **soha nem szabad éles tűzfalbetöltést futtatni** (`nft -f`, `docker compose up` a valódi interfészekkel, `install.sh`), mert a forward lánc policy dropja és a host SSH-t záró szabály a fejlesztőgépet is elzárhatja. A helyi munkához `HV_DRY_RUN=1`, `HV_SKIP_FIREWALL=1` vagy unit-teszt/mock használható; a valódi nft-viselkedés ellenőrzése a dedikált VM feladata.

## 10. Telepítés és üzemeltetés
### 10.1. Docker-es telepítés
```bash
git clone git@github.com:moodpatcher/dropjak.git
cd dropjak
sudo ./docker/setup-host.sh
cp .env.example .env
chmod 600 .env
# .env szerkesztése: HV_LAN_IF, HV_WAN_IF, HV_LAN_NET, HV_PORTAL_NET, admin
docker compose up -d --build
docker compose ps
docker compose logs -f hatarvedelem
```

A `setup-host.sh` telepíti az nftables-t, betölti a korai boot-védelmet, telepíti a `hatarvedelem-boot.service` unitot, és rögzíti a `net.ipv4.ip_forward=1` beállítást. A host SSH-hoz nem nyúl.

Az első indítás előtt admin fiókot kell beállítani, különben a portál admin felülete elérhetetlen, és a host SSH zárva marad. A szolgáltatói konzol legyen nyitva, vagy az első indítás `HV_SKIP_FIREWALL=1` értékkel történjen.

### 10.2. Build-megjegyzés
A snapshot szerint a VM-en nincs `buildx`, és a `docker compose build` nem éri el a Debian tükröket, mert a fail-closed forward lánc a build konténer egressét is blokkolja. A működő eljárás:

```bash
DOCKER_BUILDKIT=0 docker build --network host -t hatarvedelem:2 .
docker compose up -d --force-recreate
```

A `--build` szándékosan elhagyandó, ha az image már elkészült. A parancsot érdemes detached szkriptből futtatni, mert a recreate az SSH-t megszakíthatja. A 3.3.0 telepítéséhez használt mentések a 2.2. pontban szerepelnek.

### 10.3. Natív telepítés
```bash
sudo ./install.sh --wan-if eth0 --lan-if eth1 \
     --lan-net 192.168.50.0/24 --gateway-ip 192.168.50.1 \
     --portal-net 0.0.0.0/0 --portal-url http://192.168.50.1
```

A telepítő támogatott rendszerei: RHEL/AlmaLinux/Rocky/Oracle Linux 8+, Fedora, Debian 11+, Ubuntu 20.04+, SLES/openSUSE Leap; Python 3.8+ és nftables szükséges. A fájlok helye:

| Útvonal | Tartalom |
|---|---|
| `/opt/hatarvedelem` | Python modulok, `index.html`, ikonok, `services.json`, `VERSION`. |
| `/var/lib/hatarvedelem` | Állapotfájlok (systemd `StateDirectory`). |
| `/etc/nftables/hatarvedelem.nft` | Renderelt szabályok, `0600`. |
| `/etc/systemd/system/hatarvedelem.service` | Portál unit. |
| `/etc/systemd/system/hatarvedelem-firewall.service` | Korai tűzfal-unit. |
| `/etc/systemd/system/hatarvedelem-boot.service` | Docker-es korai boot-védelem (a `setup-host.sh` telepíti). |
| `/etc/sysctl.d/90-hatarvedelem.conf` | `net.ipv4.ip_forward=1`. |

A `hatarvedelem-firewall.service` `DefaultDependencies=no`, `Before=network-pre.target`, és szándékosan nincs `ExecStop`-ja: a szolgáltatás leállítása nem nyitja meg a hálózatot. A portál unit `Requires=`-szel függ a firewall-unittól, és `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, `RestrictAddressFamilies` és hasonló kármentesítést használ.

A `deploy/hv` segédeszközt az `install.sh` **nem** telepíti; Docker Compose-hoz készült, és hard-codeolt `/root/hatarvedelem` útvonalat használ.

### 10.4. Frissítés
Docker esetén:

```bash
git pull
DOCKER_BUILDKIT=0 docker build --network host -t hatarvedelem:2 .
docker compose up -d --force-recreate
```

A recreate után a dinamikus halmazok ürülnek, ezért minden kliensnek újra kell belépnie és engedélyeznie kell. Az állapotkötet megmarad. Natív telepítésnél a `install.sh` újrafuttatása frissíti a fájlokat és a unitokat; a tűzfal újratöltése a dinamikus halmazokat nem üríti, de a portál induláskori flushja igen.

### 10.5. Mentés és visszaállítás
```bash
VOLUME=$(docker volume ls -q | grep -m1 'hatarvedelem-state')
docker run --rm \
  -v "$VOLUME":/data \
  -v "$PWD":/backup \
  busybox tar czf /backup/dropjak-state.tar.gz -C /data .
```

A kötet neve a Compose-projekt nevétől függ; ezen a VM-en a projekt neve
`hatarvedelem`, ezért a kötet jellemzően `hatarvedelem_hatarvedelem-state`. A mentés tartalmazza a `users.json`, `groups.json`, `rules.json`, `audit.jsonl`, `drops.jsonl`, `fail2ban.json`, `firewall-settings.json` fájlokat. Ezek személyes adatot (e-mail) és TOTP-secretet is tartalmazhatnak, ezért a mentést ugyanolyan gondosan kell védeni, mint az élő kötetet.

### 10.6. SSH-kizárás és helyreállítás
A telepítés vagy újraindítás után a host SSH zárt lehet. Helyreállítási utak:

1. **Portál ugyanarról a nyilvános IP-ről.** Belépés, majd egy admin által hozzárendelt, TCP 22-t tartalmazó host szabály engedélyezése. Ez a normál út.
2. **Szolgáltatói konzol.** A legbiztonságosabb kiút; a telepítés előtt mindig legyen elérhető.
3. **Breakglass lánc.** A hoston, konzolról:

   ```bash
   nft add rule inet hatarvedelem breakglass \
       ip saddr <saját-ip> tcp dport 22 accept
   ```

   Használat után azonnal törölni kell a szabályt. A lánc túléli az újratöltést.
4. **`HV_SKIP_FIREWALL=1`.** Csak első indításnál vagy vészhelyzetben; a szabályok betöltése kimarad, a portál viszont elindul. Utána normál indítás és host szabály beállítása.

A `docker compose down` **nem** törli az `inet hatarvedelem` táblát; a hálózat zárt marad. A tábla tudatos eltávolítása:

```bash
sudo nft delete table inet hatarvedelem
```

Ezután a forward lánc már nem véd, ezért csak akkor, ha más mechanizmus veszi át a szerepét.

## 11. Tesztelés
### 11.1. Helyi egység- és API-tesztek
A teljes készlet a 3.3.1-es helyi munkakönyvtárban **574 teszt**, mind OK. A futtatás a repository szokásos módján:

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

A 3.3.1-es futtatás eredménye: 574 teszt OK. A portál inline JavaScriptjének szintaktikai ellenőrzése (`node --check`) szintén OK.

Tesztfájlok és darabszámok:

| Tesztfájl | Tesztek | Fókusz |
|---|---:|---|
| `tests/test_gateway.py` | 383 | Session/grant/TTL/union/revoke/HTTP/CLI alapviselkedés. |
| `tests/test_live_cli.py` | 40 | CLI parancsok, daemon-kapcsolat, helyi fallback. |
| `tests/test_revocation.py` | 29 | Visszavonás, tartósság, conntrack, restart. |
| `tests/test_host_service_guard.py` | 17 | Host service guard, portprune, kapacitás. |
| `tests/test_block_generation.py` | 15 | Block/pre-auth generálás, validáció. |
| `tests/test_audit_search.py` | 15 | Audit szűrés, normalizálás, API. |
| `tests/test_fail2ban_drop_metrics.py` | 25 | Három független jelzés, küszöb-migráció, tiltás-felszabadítás, eseménytár, env-alapértékek, audit-bontás. |
| `tests/test_revocation_lock_scope.py` | 12 | Lock-hatókör, párhuzamos engedélyezés/visszavonás. |
| `tests/test_audit_ui.py` | 9 | Audit UI eseményválasztó, szűrők. |
| `tests/test_block_precedence.py` | 8 | Block elsőbbség, pre-DNAT, atomicitás. |
| `tests/test_fail2ban_consistency.py` | 8 | fail2ban állapot és perzisztencia. |
| `tests/test_propagation_multi.py` | 7 | Többes kijelölés, részleges visszavonás, irányok. |
| `tests/test_installer.py` | 6 | Telepítő fájllista, helyőrzők, unitok. |

### 11.2. Élő E2E
A `tests/e2e_vm.py` kapuzott forgatókönyvei:

| Kapcsoló | Forgatókönyv |
|---|---|
| `HV_E2E_LONG` | Hosszabb, lassabb élő folyamatok. |
| `HV_E2E_PENDING` | Pending fiók jóváhagyása/elutasítása. |
| `HV_E2E_RESTART` | Újraindítás és újraengedélyezés. |
| `HV_E2E_MULTI` | Többes szabályválasztás. |
| `HV_E2E_RULES` | Szabálymódosítás és propagáció. |

A többes kijelölés kézi élő ellenőrzése megtörtént (`ssh,mpwerks`). A `HV_E2E_MULTI` automata futása **még nem történt meg**. A többi kapuzott forgatókönyv aktuális élő státusza ebből a dokumentumból nem állapítható meg: **NEM ELLENŐRZÖTT**.

### 11.3. Amit a tesztek nem fednek
- A valódi kernel nft/conntrack/NFLOG viselkedését csak élő VM-es futtatás igazolja; a tesztkészlet jelentős része mockolt nft-vel dolgozik.
- Az ARP/MAC-feloldás és a kapcsolószintű spoofing nem szimulálható teljesen unit tesztben.
- A Docker `DOCKER-USER` guard és a boot-tábla versenyhelyzete élő környezetet igényel.
- A többes K6 forgatókönyv és a hosszú futású restart-forgatókönyvek még nem adtak élő eredményt.

## 12. Verziótörténet
A teljes, részletes bejegyzéseket a `CHANGELOG.md` tartalmazza. Az alábbi táblázat a fő mérföldköveket foglalja össze.

| Verzió | Dátum | Fő változás |
|---|---|---|
| 2.0.0 | 2026-10-19 | Első kiadás: nftables captive portal, Docker host network, háromnyelvű UI, kétfázisú belépés, fail-closed forward. |
| 2.0.1 | 2026-10-19 | Admin űrlap megőrzi az értékeket validációs hiba után; cím egyszerűsítése; README újraírás. |
| 2.1.0 | 2026-10-19 | Spoofing/potál-bypass hardening, NFLOG drop log, custom pre-auth/block, raw/visual firewall nézet, dark theme. |
| 2.2.0 | 2026-10-20 | fail2ban login- és drop-alapú tiltás, ban képernyő, drop log forrás/cél bontás, hat reason group. |
| 2.3.0 | 2026-10-20 | Design de-slop, type scale, kontraszt, pill-ek; pre-de-slop snapshot. |
| 2.4.0 | 2026-10-20 | Opcionális TOTP 2FA QR enrollmenttel; önkiszolgáló fiókkérelmek admin jóváhagyással. |
| 2.5.0 | 2026-10-20 | Gyűjtőszabályok, szabályduplikálás, jelszógenerátor; host SSH az `admin-full`-hoz kötve. |
| 2.6.0 | 2026-10-20 | Teljes órás TTL, legfeljebb 30 nap. |
| 2.7.0 | 2026-10-20 | Forward/input irány, `allowed_input_*` halmazok; auditnapló. |
| 2.8.0 | 2026-10-20 | Vegyes irányú gyűjtők saját irány nélkül; irányonkénti érvényesítés. |
| 2.9.0 | 2026-10-20 | Verziókövetés (`VERSION`, `CHANGELOG`, portál lábléc, `/api/status`). |
| 2.10.0 | 2026-10-20 | Állítható tűzfalnév; hangos lockout-figyelmeztetések. |
| 3.0.0 | 2026-10-20 | `admin-full` és `host_ssh_v4` eltávolítása; host SSH csak explicit input szabállyal. |
| 3.0.1 | 2026-10-20 | Natív telepítő minden modult és assetet telepít; hét nft-helyőrző; drop-in. |
| 3.0.2 | 2026-10-20 | Tartós visszavonás, induláskori reconciliation, block-precedence, host-service guard, CLI daemon-út, lock-hatókör. |
| 3.1.0 | 2026-10-21 | Többes szabályválasztás, részleges visszavonás, szigorúbb TTL, többes API/UI/audit, K6 kapu. |
| 3.2.0 | 2026-10-21 | Független fail2ban drop-metrikák, küszöb 0, audit eseményválasztó és értékalapú keresés, élő UI frissítés, TTL-hint. |
| 3.2.1 | 2026-10-21 | Helyi, még nem telepített: az időtartam „óra” egységfelirata és a TTL-hint ismétlésének megszüntetése. |
| 3.3.0 | 2026-10-21 | Élő: a fail2ban három jelzése (belépés, csomagszám, célportok) teljesen független kapcsolóval; a 0 küszöb elutasítása és a mentett 0 migrálása; a drop-mesterkapcsoló eltávolítása; független tiltás-felszabadítás. |
| 3.3.1 | 2026-10-21 | Helyi, még nem telepített: a közös tiltáshossz a nem kapcsolható „Közös beállítások” csoportban; a validációs üzenet fordított kulcsa; üres/letiltott mező mentése a mentett értékkel; `login_count`/`drop_count` az auditban; erősebb tesztek. |

## 13. Progress és nyitott pontok
### 13.1. Kész és élő
- 3.3.0 image fut a VM-en; `/api/status` `ok: true`, verzió `3.3.0`; a futó image digestje `sha256:55b1b218d361c7a2451d4d0c0b90a7199dfd189591fff401a65d2ba7be90bc97`.
- A 3.3.0 élő:
  1. a fail2ban három jelzése (sikertelen belépés, eldobott csomagok, különböző célportok) teljesen független kapcsolóval működik;
  2. a 0 küszöb megszűnt: a `drop_max`/`drop_ports` legalább 1, a mentett 0 migrálódik;
  3. a drop-mesterkapcsoló eltávolítása és a jelzésenkénti tiltás-felszabadítás él;
  4. a 3.2.0-s élő UI-frissítés, TTL-hint, audit eseményválasztó és értékalapú keresés továbbra is része az image-nek.
- A recreate a dinamikus halmazok ürítése miatt bezárta a host SSH-t; az újraengedélyezés a portálon történik.
- A többes kijelölés kézi élő ellenőrzése megtörtént.
- A helyi teljes tesztkészlet a 3.3.1-es munkakönyvtárban 574 teszt OK; a JS szintaktikai ellenőrzés OK.
- A 3.3.0 telepítés előtti mentések rendelkezésre állnak.
- Az `.env` integritása a recreate előtt nem változott; a VM-en `.secret` nem volt jelen.
- A helyi 3.3.1 javításai (közös tiltáshossz, validációs üzenet, üres/letiltott mező, audit bontás) **még nincsenek élőben**.

### 13.2. Helyi kód, de élő visszaigazolás nélkül
- A `tests/test_propagation_multi.py` hét regressziós tesztje helyben fut, de a `HV_E2E_MULTI` élő automata változat nem.
- A git munkakönyvtár nem tiszta; a helyi és az élő kód azonossága nem bitre ellenőrzött.
- A `docs/propagation-matrix.md` által leírt maradék runtime-feltételezések egy része csak élő méréssel lenne lezárható.
- A 3.3.1 javításai helyben teszteltek, de a VM-en nem futnak.

### 13.3. Terv / elhalasztva
- **Több site-beállítás.** A fejlesztői home `todo.txt` fájlja a snapshot szerint már csak ezt az elhalasztott elemet tartalmazza; a részleteket a felhasználóval kell egyeztetni. Ez a dokumentum nem dönt róla.
- **Caddy / TLS reverse proxy.** A `docs/caddy-proxy-terv.md` terve, amelynek állapota szó szerint „terv — nincs implementálva”. A portál jelenleg plain HTTP; ha WAN-ról elérhető, a `HV_COOKIE_SECURE=1` csak a sütit védi, a jelszót és a TOTP-adatokat nem. A `HV_PORTAL_NET` szűkítése vagy TLS-terminálás szükséges.
- **Élő E2E lefedettség.** A K6 többes forgatókönyv és a többi kapuzott élő szcenárió eredménye még hiányzik.
- **Email-értesítés / fiókkérelem-flow bővítése.** Az e-mail csak kontaktadat; nincs kiküldés, visszaigazolás, lemondás, lejárat vagy bulk művelet.

### 13.4. Nem ellenőrzött pontok
- A VM konténer uptime-ja, konténer-ID-je, PID-jei; a két mentési archívum fájlszintű tartalma és visszaállíthatósága.
- A K1–K5 élő E2E eredménye; a git commit/push állapot és a helyi és élő forrás bitre azonossága.
- A `.env` tényleges értékei (csak a hash ismert; a tartalom szándékosan nem került beolvasásra).
- A VM-en futó Minecraft konténer részletes konfigurációja (a repóban csak az nft-sablon `172.30.0.2` kivétele látható), és a natív `install.sh` unitjainak állapota a Docker-es VM-en.

## 14. Fájltérkép
| Útvonal | Szerep |
|---|---|
| `VERSION`, `CHANGELOG.md` | Verzió és verziótörténet. |
| `README.md`, `PROJEKT-ALLAPOT.md` | Felhasználói és projektállapot-dokumentáció. |
| `server.py` | HTTP API, portál, admin, auth. |
| `gateway.py` | Szabályok, munkamenetek, nft-hívások, visszavonás. |
| `fail2ban.py`, `droplog.py` | Tiltás és NFLOG-alapú drop-napló. |
| `settings_store.py` | Beállítások validálása, atomikus írás. |
| `index.html`, `icon.png`, `blocked.png` | Portál/admin UI és assetek. |
| `services.json` | Kezdő szolgáltatás- és scenario-katalógus. |
| `docker-compose.yml`, `Dockerfile` | Docker host network, state volume, healthcheck, image. |
| `install.sh`, `.env.example`, `.dockerignore`, `.gitignore` | Natív telepítő, konfigurációs minta, Docker- és git-kizárások. |
| `docker/entrypoint.sh` | Env-validáció, renderelés, nft, halmazürítés, boot-tábla, Docker guard, watchdog, setpriv. |
| `docker/setup-host.sh` | Boot nft/unit és `ip_forward` a hoston. |
| `deploy/hatarvedelem.nft` | Teljes nftables-sablon hét helyőrzővel. |
| `deploy/hatarvedelem.service`, `deploy/hatarvedelem-firewall.service`, `deploy/hatarvedelem-boot.service`, `deploy/hatarvedelem-boot.nft` | Systemd unitok és a korai boot-tábla. |
| `deploy/hv`, `deploy/HELYI-UTMUTATO.md` | Docker operatív segédeszköz és helyi útmutató. |
| `docs/audit-log.md`, `docs/host-rules.md` | Audit és host/SSH szabályok. |
| `docs/propagation-matrix.md`, `docs/rule-collections.md` | Invarianciák/mutációs mátrix és gyűjtőszemantika. |
| `docs/totp-2fa.md`, `docs/account-requests.md` | 2FA és fiókkérelmek. |
| `docs/caddy-proxy-terv.md`, `docs/antislop-terv-2026-10-20.md`, `docs/design-backup-2026-10-20/` | Tervek és design-snapshot. |
| `tests/test_gateway.py`, `tests/test_live_cli.py`, `tests/test_revocation*.py` | Alap, CLI, visszavonás és lock-hatókör. |
| `tests/test_host_service_guard.py`, `tests/test_block_*.py` | Host guard és block/pre-auth. |
| `tests/test_fail2ban_*.py`, `tests/test_audit_*.py` | fail2ban és audit. |
| `tests/test_propagation_multi.py`, `tests/test_installer.py`, `tests/e2e_vm.py` | Többes kijelölés, telepítő, élő E2E. |

A nyitott feladatok listája nem a repóban, hanem a fejlesztői home
`todo.txt` fájljában él (`/home/moodpatcher/todo.txt`).

## 15. Gyorsparancsok és hibaelhárítás
### 15.1. Állapot és naplók
```bash
# Docker
docker compose ps
docker compose logs -f hatarvedelem
curl -fsS http://127.0.0.1:8100/api/status | python3 -m json.tool

# A deploy/hv segédeszközzel (Docker, /root/hatarvedelem)
./deploy/hv status
./deploy/hv logs
./deploy/hv restart
./deploy/hv backup
./deploy/hv test
./deploy/hv e2e
./deploy/hv where
```

A `hv` parancsok a snapshot szerint: `status`, `logs`, `restart`, `rebuild`, `edit`, `services`, `users`, `add`, `passwd`, `del`, `backup`, `test`, `e2e`, `where`.

### 15.2. Tűzfal ellenőrzése
```bash
sudo nft list table inet hatarvedelem
sudo nft list set inet hatarvedelem allowed_tcp
sudo nft list set inet hatarvedelem allowed_input_tcp
sudo nft list set inet hatarvedelem banned_v4
sudo conntrack -L | head
sudo nft list table inet hatarvedelem_boot   # csak boot idején
```

A `host_service_tcp` / `host_service_udp` csak bővül; ha egy port ott marad, az önmagában nem hiba, csak szigorúbb established-ellenőrzést jelent.

### 15.3. Gyakori hibák
| Tünet | Valószínű ok | Teendő |
|---|---|---|
| `docker compose build` nem ér el tükröt | A fail-closed forward lánc blokkolja a build konténer egressét; nincs buildx. | `DOCKER_BUILDKIT=0 docker build --network host -t hatarvedelem:2 .`, majd `up -d --force-recreate`. |
| SSH megszakadt telepítés után | Az induláskori flush ürítette az `allowed_input_tcp`-t. | Portál ugyanarról az IP-ről, vagy szolgáltatói konzol, vagy breakglass. |
| A portál nem indul | Hiányzó kötelező env, hibás CIDR, nft-hiba, állapotfájl-hiba. | `docker compose logs`; ellenőrizni `HV_LAN_IF`, `HV_WAN_IF`, `HV_LAN_NET`, `HV_PORTAL_NET`. |
| A portál elérhető, de a hálózat nem | Nincs érvényes grant, lejárt TTL, fail2ban, block, MAC-eltérés. | `/api/status`, admin Sessions/Firewall, `nft list set`, `conntrack`. |
| A host SSH nem nyílik | Nincs explicit TCP 22-t tartalmazó host szabály, vagy nincs aktív munkamenet. | Admin Rules/Users; host szabály és hozzárendelés; portál belépés ugyanarról az IP-ről. |
| A drop log üres | `HV_DROP_LOG=0`, rossz NFLOG csoport, más fogyasztó, kernel NFLOG hiánya. | `HV_DROP_LOG=1`, csoport egyezés, `dmesg`/`journalctl`. |
| A fail2ban kizárta a saját IP-t | Túl alacsony küszöb, NAT mögötti scanner, kézi ban. | Konzol + `server.py fail2ban unban <ip>` vagy `unban-all`; küszöb emelése. |
| A felhasználó belép, de nem kap hozzáférést | pending fiók, letiltott fiók, rossz TOTP, `must_change_password`, nincs szabály kiválasztva. | Admin Users; pending jóváhagyás; TOTP reset; jelszócsere; szabályválasztás. |
| A felhasználó be sem tud lépni | pending fiók, letiltott fiók, rossz jelszó/TOTP, captcha-hiba, fail2ban. | Admin Users; pending jóváhagyás; TOTP reset; tiltás feloldása. |
| Az admin UI nem frissül | Régi szabály-snapshot, visszavont választás. | 3.2.0-ban a 30 másodperces poll frissít; **Módosítás** friss státuszt kér. |
| `permission denied` az nft-hez | A konténer nem kapta meg a `NET_ADMIN`-t, vagy natív módban rossz capability. | Compose `cap_add`, systemd `AmbientCapabilities`. |

### 15.4. Diagnosztikai elvek
- Először a portál saját állapotát nézd (`/api/status`, admin Sessions/Firewall), csak utána a kernelt.
- A kernel halmaz és a portál munkamenet-táblája eltérhet: a halmaz TTL-je a mérvadó a forgalom szempontjából, a munkamenet a felületén.
- Ne futtass `nft flush ruleset`-et: az összes láncot törölné, nem csak a sajátot.
- A `block` módosítása nem igényel conntrack flush-t; a grant visszavonása igen, de azt a portál végzi.
- A `breakglass` szabály után ne felejtsd el törölni a szabályt.

## 16. Függelék: fogalmak
| Fogalom | Magyarázat |
|---|---|
| **Captive portal / fail-closed** | Belépőoldal; hiba vagy hiányzó konfiguráció esetén a rendszer zárt marad. |
| **nftables / set / timeout** | Kerneloldali szűrő-NAT keretrendszer; a halmaz elemei kerneloldali lejárattal bírnak. |
| **Forward / input (host)** | A gatewayen átmenő, illetve a gateway gép saját maga felé menő forgalom. |
| **DNAT / pre-DNAT** | Célcím-átírás; a grant és a block az eredeti, DNAT előtti célt nézi. |
| **Conntrack** | Kapcsolatkövető tábla; visszavonáskor a meglévő folyamokat is törölni kell. |
| **MAC-kötés / TTL / grant** | Az engedély IP-hez és ARP-ből feloldott MAC-hez kötött, TTL-lel; a grant a konkrét kernel-elemek. |
| **Collection** | Több egyedi szabály uniója; nincs saját iránya és portja. |
| **Proof-of-work / Turnstile** | Helyi captcha számítási feladattal, illetve opcionális Cloudflare captcha. |
| **TOTP / recovery code** | Időalapú 6 jegyű kód, illetve egyszer használatos tartalék kód. |
| **NFLOG / drop log** | Netfilter-naplózás netlink csoportra; abból épül a csak fejlécet tartalmazó JSONL napló. |
| **fail2ban** | Itt a beépített, nem a klasszikus daemon: login- és drop-alapú tiltás. |
| **Breakglass / DOCKER-USER** | Vészhelyzeti, újratöltést túlélő SSH-lánc, illetve a Docker felhasználói lánca. |
| **Watchdog / dry run** | Az entrypoint tűzfal-figyelője; `HV_DRY_RUN=1` esetén a portál nem ír nft-t. |

## 17. A dokumentum változásnaplója
| Dátum | Változás |
|---|---|
| 2026-10-21 | Első kiadás. A 3.2.0-s snapshot, a helyi repository és a megadott élő tények alapján. A dokumentum nem tartalmaz titkot; a bizonytalan pontok „NEM ELLENŐRZÖTT” jelölést kaptak. |
| 2026-10-21 | Ellenőrző átnézés: a `git clone` és a biztonsági mentés parancsa, az audit Logs szűrők, a szabály-TTL példák, a forward lánc sorrendje, a `todo.txt` helye és a fájltérkép pontosítva. |
| 2026-10-21 | 3.2.1: az időtartam óra-felirata és a TTL-hint ismétlésének javítása; a dokumentum élő 3.2.0 / helyi 3.2.1 állapotot jelöl. |
| 2026-10-21 | 3.3.0: a fail2ban három jelzésének független kapcsolása, a 0 küszöb megszüntetése és a régi 0 migrálása; a dokumentum élő 3.2.0 / helyi 3.3.0 állapotot jelöl. A változtatás csak helyi, nincs telepítve. |
| 2026-10-21 | 3.3.1: a 3.3.0 élő telepítése (image `sha256:55b1…`, `/api/status` 3.3.0, mentések `20261021-153034`); a helyi fa 3.3.1, amely a közös tiltáshosszt, a validációs üzenetet, az üres/letiltott mező mentését, az audit bontását és erősebb teszteket tartalmazza, de nincs telepítve. Az élő 3.3.0 és a helyi 3.3.1 külön szerepel. |
