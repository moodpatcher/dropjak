# Dropjak — hálózati belépőkapu

Egy Linux VM, amely routerként működik a kliensei és az internet között, de
**alapértelmezésben minden továbbított forgalmat blokkol**. A kliens a
belépőoldalon (portálon) felhasználónévvel és jelszóval belép, majd a
számára kiosztott **hozzáférési szabályok** közül választ, és megadja,
**mennyi ideig** (1 perc és 24 óra között, percben vagy órában) szeretné
használni a hálózatot. A szabály **portokat** rendel a felhasználóhoz: egy
szabály több TCP- és UDP-portot is tartalmazhat, emellett ICMP-t (ping)
vagy teljes hozzáférést adhat. A kapu csak a kiválasztott célportokra
nyitja meg az adott kliens IPv4-címét az nftables dinamikus halmazaiban.
Docker által publikált konténernél a host portját kell megadni: a szabály
a DNAT előtti célportra illeszkedik, ezért a forward engedély a
konténerhez is eljut. A munkamenet lejártával — vagy kilépéskor — az
engedély automatikusan megszűnik.

A felület magyar, angol és német nyelven érhető el. A nyelv a fejléc
nyelvválasztójával váltható, `?lang=hu`, `?lang=en` vagy `?lang=de`
paraméterrel kényszeríthető, és a böngésző megjegyzi. A naplóesemények
neve és az ismert szerverüzenetek is lefordulnak; a felhasználók által
létrehozott nevek és leírások változatlanok maradnak.

A szabályokat, csoportokat és felhasználókat az adminisztrátor a portál
**Admin** paneljén kezeli. Az admin beépítetten mindig megkapja a
korlátozás nélküli `admin-full` szabályt. Minden lényeges esemény
(portálmegnyitás, belépés, szabályválasztás, kilépés, lejárat,
admin-művelet) részletes, rotált naplóba kerül.

```
        belső hálózat                         internet
  [kliens] --- LAN ---> [ Dropjak VM ] --- WAN ---> [router/ISP]
                          nftables: forward policy drop
                          allowed_v4 / allowed_tcp / allowed_udp / allowed_icmp
                          portál: HTTP :80
```

A portál a projekt eredeti login-template felülete, most valódi
hitelesítéssel, kétfázisú hozzáférés-választással, munkamenetekkel és
tűzfal-integrációval.

## Hogyan működik

1. A még nem engedélyezett kliens HTTP-kérése a 80-as portra a PREROUTING
   láncban a portálra kerül (`redirect to :PORT`).
2. A portál kiszolgál egy proof-of-work captchát, majd bekéri a
   felhasználónevet és a jelszót.
3. A helyes jelszó **még nem nyit hálózatot**: a szerver csak egy függő
   (pending) munkamenetet hoz létre, amely a `HV_AUTH_TTL` ideig érvényes.
4. A felület ezután kirajzolja azokat a hozzáférési szabályokat, amelyeket
   az admin a felhasználóhoz közvetlenül vagy a csoportjain keresztül
   rendelt. A kiválasztott szabály azonosítóját és az órában vagy percben
   megadott időtartamot a böngésző a `POST /api/access` végpontra küldi. A
   szerver ellenőrzi, hogy a szabály tényleg a felhasználóé, és hogy az idő
   a `HV_MIN_TTL`–`HV_MAX_TTL` és a szabály saját maximuma közé esik
   (alapból 60–86400 másodperc).
5. Csak ezután módosítja a tűzfalat, egyetlen nft-szkripttel. A szabály
   portjai határozzák meg, mi nyílik meg:
   - teljes hozzáférés → `allowed_v4 { <kliens-ip> timeout <ttl>s }`
   - TCP/UDP portok → `allowed_tcp` / `allowed_udp`
     `{ <kliens-ip> . <célport> timeout <ttl>s }`
   - ICMP → `allowed_icmp { <kliens-ip> timeout <ttl>s }`
   - host SSH → `host_ssh_v4 { <kliens-ip> timeout <ttl>s }`

   Ha az nft-hívás nem sikerül, a szerver visszavonja a részleges
   engedélyeket, és a munkamenet függő állapotban marad (fail-closed).
6. A forward lánc csak a kiválasztott `(forrás-IP, célport)` párokat és a
   hozzájuk tartozó, `ct state established,related` visszirányú forgalmat
   engedi. A `HV_NFT_SET` (`allowed_v4`) halmaz a teljes hozzáférést jelenti.
   Az input lánc a host 22-es portját csak a `host_ssh_v4` halmazból
   engedi, tehát SSH-val is csak a portálon engedélyezett IP-ről lehet
   bejutni.
7. Kilépéskor a szerver törli a kliens összes halmazelemét és kiüríti a
   conntrack-bejegyzéseit. A munkamenet lejártakor ugyanez történik.
   Ha a szerver közben leáll, a kernel a beállított timeoutnál magától
   törli az engedélyt — a hozzáférés nem marad nyitva.
8. A szolgáltatás indulásakor alapból kiüríti az összes dinamikus halmazt
   (`HV_FLUSH_ON_START=1`), beleértve a `host_ssh_v4`-et is, tehát egy
   újraindítás mindenkit kiléptet.

## Telepítési módok

- **Docker (ajánlott):** a portál és az nftables egy konténerben fut. A
  konténer `network_mode: host` módban dolgozik, mert csak így érheti el a
  VM forward-láncát. A Docker bridge-hálózata erre nem alkalmas.
- **Bare-metal systemd:** a program közvetlenül a hoston fut, két systemd
  unit alatt. Akkor hasznos, ha nincs Docker a VM-en, vagy a legkisebb
  támadási felületet szeretnéd.

A két mód ugyanazt a `gateway.py`/`server.py` magot és ugyanazt az
idempotens nftables-sablont használja. Egy VM-en csak az egyiket futtasd.

## Követelmények

### Docker

- Linux host, működő Docker Engine 20.10+ és Docker Compose v2
  (`docker compose version`)
- nftables a host kernelben és a hoston az `nft` bináris (a
  `setup-host.sh` telepíti, ha kell); az `nft` és a `conntrack` a képen
  belül is megtalálható
- két hálózati interfész (vagy VLAN): egy a kliensek, egy az internet felé
- root (vagy a `docker` csoportba tartozó felhasználó) a konténer
  indításához; a `docker/setup-host.sh` futtatásához root kell
- `net.ipv4.ip_forward=1` a hoston (a `setup-host.sh` tartósan rögzíti;
  host-hálózat mellett a compose nem tudja beállítani)
- opcionális: `dnsmasq` a hoston a DHCP/DNS-hez

A Docker-kép Debian slim alapon készül; a host disztribúciója ettől
független, a szabályok a host kernel nftables-ét használják.

### Bare-metal (systemd)

- Linux systemd-vel, nftables és Python 3.8 vagy újabb (a program csak a
  standard könyvtárat használja)
- két hálózati interfész (vagy VLAN-ok): egy a kliensek, egy az internet felé
- root a telepítéshez
- opcionális: `conntrack`/`conntrack-tools` (a kilépés utáni azonnali
  kapcsolatbontáshoz), `dnsmasq` (DHCP/DNS a klienseknek)

A támogatott rendszerek és a hozzájuk tartozó csomagnevek:

| Rendszer | Csomagkezelő | nftables | Python | iproute | felhasználókezelés |
|---|---|---|---|---|---|
| RHEL / AlmaLinux / Rocky / Oracle 8+ | dnf vagy yum | `nftables` | `python3` (RHEL 8: `python39`) | `iproute` | `shadow-utils` |
| Fedora | dnf | `nftables` | `python3` | `iproute` | `shadow-utils` |
| Debian 11+, Ubuntu 20.04+ | apt-get | `nftables` | `python3` | `iproute2` | `passwd` |
| SLES / openSUSE Leap | zypper | `nftables` | `python3` (3.8+) | `iproute2` | `shadow` |

A telepítő felismeri a csomagkezelőt, és felajánlja a hiányzó csomagok
telepítését. RHEL 8-on a `python3` még 3.6, ezért a telepítő a `python39`
csomagot is felajánlja, és a unit a `/usr/bin/python3.9` interpretált
használja. RHEL 7 és Debian 10 nem támogatott (nincs bennük Python 3.8).

A **firewalld** és a **ufw** nem használható mellette: a telepítő
megerősítés után kikapcsolja őket (a `--yes` ezt is jóváhagyja). A
szabályok saját nftables-táblában, a `hatarvedelem-firewall.service` alatt
vannak. Ez a unit a boot során korán, a hálózat beindulása előtt betölti
őket, és ha létezik, a disztribúció `nftables.service`-e után fut.

## Telepítés Dockerrel (ajánlott)

A konténer a host hálózati névterében fut. Ez nem kényelmi beállítás: a
`forward` lánc a host névterében van, a Docker saját bridge-hálózata pedig
elkülönített névtér, ahol az itt betöltött szabályok nem érvényesülnének.
Ezért a compose `network_mode: host`-ot és `CAP_NET_ADMIN`-t használ, és
nincs `ports:` leképezés.

### 1. Host előkészítése

A Docker csak a boot késői szakaszában indul el. Hogy addig se menjen át
szabályozatlan forgalom, telepíts egy korai forward-tiltó unitot a hostra:

```bash
sudo ./docker/setup-host.sh
```

A szkript:

- felajánlja az `nftables` telepítését, ha nincs a hoston;
- betölti a `/etc/nftables/hatarvedelem-boot.nft`-t, amely a `forward`
  láncon `policy drop`-ot ad (az SSH-t nem érinti);
- telepíti és engedélyezi a `hatarvedelem-boot.service`-t, ami a Docker
  előtt fut;
- rögzíti a `net.ipv4.ip_forward=1` beállítást a
  `/etc/sysctl.d/90-hatarvedelem.conf` fájlban.

Ha a Docker már fut, a szkript nem tölti be azonnal a boot-táblát (hogy ne
szakítsa meg a forgalmat); a következő bootkor lép életbe. A konténer a
végleges szabályok betöltése után törli a boot-táblát, így a kettő nem
ütközik.

> A `setup-host.sh` nélkül is működik a rendszer, de a boot és a konténer
> indulása között a forward-lánc szabályozatlan lehet, és az `ip_forward`
> is kézzel állítandó. Éles átjárón a szkript futtatása javasolt.
>
> A compose szándékosan nem használ `sysctls:` bejegyzést: host-hálózat
> mellett a runc elutasítja a `net.*` sysctl-eket.

### 2. Konfiguráció

```bash
cp .env.example .env
editor .env
```

A kötelező értékek:

| Változó | Példa | Jelentés |
|---|---|---|
| `HV_LAN_IF` | `eth1` | a kliensek felé néző interfész |
| `HV_WAN_IF` | `eth0` | az internet felé néző interfész |
| `HV_LAN_NET` | `192.168.10.0/24` | a kliensek hálózata |
| `HV_PORTAL_NET` | `0.0.0.0/0` | ahonnan a **portál** elérhető |

A portál a LAN felől minden kliens számára elérhető. A WAN/internet felől a
`HV_PORTAL_NET` szabályozza: `0.0.0.0/0` értékkel bárhonnan, szűkebb
hálózattal csak onnan. Ha a `HV_PORTAL_NET` üres, a `HV_MGMT_NET` értékét
használja alapértékként.

**SSH a hostra:** a `HV_MGMT_NET` már **nem** ad SSH-hozzáférést. A host SSH
(22-es port) kizárólag akkor nyílik meg, ha ugyanarról az IP-címről valaki a
portálon sikeresen belépett, kiválasztott egy hozzáférési szabályt és a
TTL-t. A jelszó megadása önmagában még nem elég. Kilépéskor azonnal, a TTL
lejártakor pedig a kernel-timeouttal zárul. Ezért:

- a böngésző és az SSH ugyanarról a nyilvános IP-ről induljon (VPN esetén
  ugyanaz az exit IP);
- a host SSH saját kulcsos/jelszavas védelme természetesen továbbra is él;
- **mindig legyen egy másik út a VM-hez** (szolgáltatói konzol), mert ha a
  portál nem indul el, SSH-val sem lehet bemenni. A vészhelyzeti
  hozzáférést a `deploy/hatarvedelem.nft` input láncában kommentben jelzett
  sorral lehet ideiglenesen megnyitni.

Az interfészneveket az `ip -br link` mutatja.

A többi változó (`PORT`, `HV_SESSION_TTL`, `HV_MIN_TTL`, `HV_MAX_TTL`,
`HV_POW_DIFFICULTY`, ...) leírása a [Beállítások](#beállítások) szakaszban
van.

### 3. Indítás

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f hatarvedelem
```

A konténer naplójában ezeknek kell megjelennie:

```
[hatarvedelem] szabályfájl elkészült: /run/hatarvedelem.nft
[hatarvedelem] szabályok betöltése (host hálózati névtér)
[hatarvedelem] portál indítása a 8100-as porton
```

A portál alapból a host 8100-as portján hallgat; a 80-as portra érkező,
még nem engedélyezett kliensforgalmat az nft a 8100-ra irányítja. A
böngészőben a `http://<kapu-lan-címe>:8100/` vagy a `http://<kapu-lan-címe>/`
nyitható meg. A healthcheck a `/api/status` végpontot figyeli.

### 4. Első felhasználó és adminisztráció

Az első fiókot a legegyszerűbb a `.env`-ben megadott admin fiókkal
létrehozni (`HV_ADMIN_ENABLED=1`). Ez `admin` szerepkörrel jön létre, és a
portálon bejelentkezve azonnal elérhető az **Admin** fül, ahol további
felhasználók, csoportok és hozzáférési szabályok hozhatók létre. A
részletes leírás a [Felhasználók kezelése](#felhasználók-kezelése)
szakaszban van.

Ha nem Compose-ból akarsz admint létrehozni, a CLI-vel is felvehetsz
felhasználót. A CLI alapból `user` szerepkört ad; adminná a felület
**Admin → Felhasználók** fülén lehet tenni:

```bash
printf '%s\n' 'hosszu-jelszo' | docker compose run --rm -T hatarvedelem \
  python3 /opt/hatarvedelem/server.py user add alice --password-stdin
```

A `docker compose run` a konténer belépési pontján keresztül fut, így a
`users.json` a `hatarvedelem` felhasználó tulajdonában jön létre a
`hatarvedelem-state` kötetben. A futó portál a fájl változását a következő
belépésnél látja; nem kell újraindítani.

Jelszócsere, törlés, lista:

```bash
printf '%s\n' 'uj-jelszo' | docker compose run --rm -T hatarvedelem \
  python3 /opt/hatarvedelem/server.py user passwd alice --password-stdin
docker compose run --rm -T hatarvedelem \
  python3 /opt/hatarvedelem/server.py user del alice
docker compose run --rm -T hatarvedelem \
  python3 /opt/hatarvedelem/server.py user list
```

A hozzáférési szabályokat, csoportokat és a felhasználói hozzárendeléseket
nem kell kézzel szerkeszteni: ezeket az admin felület kezeli, és a
változások azonnal érvényesülnek (a felhasználó- és csoporthozzárendelés
módosítása a már futó munkameneteket is visszavonja, ha az adott szabály
már nem engedélyezett számára).

### Frissítés

```bash
docker compose up -d --build
```

A konténer újraindul. A belépési pont idempotensen újratölti a
szabályokat, majd a portál induláskor kiüríti a dinamikus halmazokat
(`allowed_v4`, `allowed_tcp`, `allowed_udp`, `allowed_icmp`,
`host_ssh_v4`; `HV_FLUSH_ON_START=1`), tehát **mindenki kijelentkezik**.
A `users.json`, `rules.json`, `groups.json` és a naplófájlok a kötetben
maradnak.

### Állapot és biztonsági mentés

Az állapot a `hatarvedelem-state` Docker-kötetben van
(`/var/lib/hatarvedelem`):

| Fájl | Tartalom |
|---|---|
| `users.json` | felhasználók, szerepkörök, közvetlen szabályok |
| `groups.json` | csoportok, tagságok és csoportszabályok |
| `rules.json` | admin által létrehozott hozzáférési szabályok |
| `audit.jsonl` | részletes JSONL auditnapló (rotálva: `audit.jsonl.1` …) |

A JSON-fájlok mellett `<fájlnév>.lock` zárolási fájlok lehetnek; ezek
átmeneti jellegűek. A captcha HMAC-kulcsa folyamatonként generálódik,
ezért nem kell menteni: a portál újraindítása után a korábbi kihívások
úgyis érvénytelenné válnak.

A kötet a `docker compose down` után is megmarad; csak a
`docker compose down -v` törli.

```bash
# mentés (a kötet tényleges nevét a docker volume ls mutatja)
docker run --rm -v hatarvedelem_hatarvedelem-state:/data -v "$PWD":/backup \
  busybox tar czf /backup/hatarvedelem-state.tar.gz -C /data .
```

A kötet neve a compose projekt nevétől függ (alapból
`<mappa>_hatarvedelem-state`).

### Docker-specifikus viselkedés

- **Egy példány:** a `network_mode: host` és a közös nftables-tábla miatt
  egyszerre csak egy konténer futhat.
- **Más konténerek:** a `forward` láncon `policy drop` van érvényben. A
  hoston futó, bridge-hálózatot használó egyéb konténerek forgalmát ez
  érintheti. Dedikált átjáró VM-en ez nem probléma; több szolgáltatás
  esetén teszteld, vagy használj külön VM-et.
- **Docker FORWARD-policy:** a Docker a saját `ip filter FORWARD` láncában
  `policy drop`-ot használ, ami a mi `inet` táblánktól függetlenül is
  eldobná a továbbított csomagokat. A belépési pont ezért a Docker
  hivatalos kiterjesztési pontjára, a `DOCKER-USER` láncra szúr két
  `accept` szabályt a LAN-interfészre (`hv-docker-fwd-in` /
  `hv-docker-fwd-out` megjegyzéssel). A tényleges engedélyezést továbbra
  is az `inet hatarvedelem` dinamikus halmazai végzik. Ez a Docker
  alapértelmezett, nft-alapú iptables-backendjét feltételezi; legacy
  iptables esetén a lánc nem látható, és a belépés utáni forward a Docker
  policy drop miatt elakadhat.
- **Host-szolgáltatások:** az `input` lánc is `policy drop`; a hoston futó
  egyéb szolgáltatások csak a sablonban felsorolt kivételekkel (loopback,
  LAN DNS/DHCP, portál, valamint a portál-munkamenethez kötött host SSH)
  érhetők el. Dedikált átjárón ez a kívánt viselkedés.
- **Leállítás:** a `docker compose down` nem törli az nftables-táblát, mert
  a biztonságos viselkedés a fail-closed. A már belépett kliensek a kernel
  timeoutjáig elérhetik a hálózatot, új belépés viszont nincs, mert a
  portál leállt. A `DOCKER-USER` áthidaló szabályok is megmaradnak, de
  önmagukban nem nyitják meg a forwardot, mert az `inet` tábla
  `policy drop`-ja érvényesül. A tábla eltávolítása külön művelet:
  `sudo nft delete table inet hatarvedelem` (ez a DOCKER-USER szabályokkal
  együtt megnyitja a forwardot).
- **Boot:** a `hatarvedelem-boot.service` a Docker előtt `drop`-ol, a
  konténer indulásakor átveszi a helyét. Ha a Docker nem indul el, a
  forward tiltva marad (fail-closed).
- **ip_forward:** a hoston kell `1`-nek lennie. A `setup-host.sh` beállítja
  és a `/etc/sysctl.d/90-hatarvedelem.conf`-ba írja; a compose `sysctls`
  bejegyzést nem használ, mert host-hálózat mellett a runc elutasítja.
- **SELinux:** a névvel ellátott kötetet a Docker kezeli; nincs kézi
  relabel, bind mount nincs.
- **firewalld/ufw:** a Dockeres mód nem kapcsolja ki őket. Ha aktívak,
  ellenőrizd, hogy nem ütköznek a forward-szabályokkal; dedikált átjárón a
  `setup-host.sh` figyelmeztet.

## Telepítés bare-metal rendszeren (systemd)

Másold a projektet a VM-re, majd rootként:

```bash
sudo ./install.sh --wan-if eth0 --lan-if eth1
```

Az installer:

- felismeri a disztribúciót és a csomagkezelőt, majd felajánlja a hiányzó
  `nftables`, Python 3.8+, iproute és felhasználókezelő csomagok (valamint
  opcionálisan a `conntrack` eszköz) telepítését;
- autodetektálja a WAN interfészt, a LAN interfész IPv4-címét pedig felkínálja
  (a LAN interfészt megkérdezi);
- a portál forrás-hálózatát az SSH-forrásból próbálja kitalálni, és ezt
  használja alapértékként (`--portal-net`); a portál forrása külön állítható
  (nyilvános portálhoz `0.0.0.0/0`);
- kikapcsolja a firewalld-t, a ufw-t, valamint a bootkori iptables-szabályokat
  betöltő `netfilter-persistent`/`iptables` szolgáltatásokat (megerősítés
  után);
- átmásolja a programot az `/opt/hatarvedelem` könyvtárba, létrehozza a
  `hatarvedelem` rendszerfelhasználót és a `/var/lib/hatarvedelem` állapot-
  könyvtárat;
- legenerálja és `nft -c`-vel ellenőrzi az `/etc/nftables/hatarvedelem.nft`
  fájlt. A fájl **idempotens**: ismételt betöltés nem duplázza a szabályokat,
  és a belépett kliensek halmazelemei megmaradnak;
- bekapcsolja az `ip_forward`-ot, betölti a szabályokat, telepíti a
  `hatarvedelem-firewall.service`-t és a `hatarvedelem.service`-t, majd
  elindítja őket;
- létrehozhatja az első felhasználót.

A `--yes` nem csak a kérdéseket hagyja ki: a hiányzó csomagokat is telepíti,
és a firewalld/ufw-t is kikapcsolja. Csak akkor használd, ha ezzel egyetértesz.

Példa szűk portálforrással és nem alapértelmezett portálcímmel:

```bash
sudo ./install.sh --wan-if eth0 --lan-if eth1 \
     --portal-net 192.168.1.50/32 \
     --portal-url http://192.168.50.1
```

Nem interaktív telepítés (felhasználó nélkül):

```bash
sudo ./install.sh --wan-if eth0 --lan-if eth1 --yes --skip-user
```

> **SSH:** a meglévő kapcsolatot a conntrack-szabály életben tartja, de egy
> **új** SSH-kapcsolat csak akkor jön létre, ha ugyanarról az IP-címről a
> portálon beléptél, és engedélyezted a hozzáférést (bármely szabályt
> kiválasztva, a TTL megadásával). A `--portal-net` csak a portál forrását
> adja meg, SSH-t nem engedélyez.
> Telepítés után ezért előbb a portálon lépj be, vagy maradj a meglévő SSH-
> kapcsolatban. Ha a portál nem indul el, csak a szolgáltatói konzol segít.
>
> Ha nem SSH-ból telepítesz, és nincs felismerhető SSH-forrás, a portál
> forrása alapból a **teljes LAN** lesz (hogy ne zárj ki senkit). Éles
> használatban mindig add meg szűkebben, például
> `--portal-net 192.168.50.10/32`, vagy hagyd nyilvánosan
> (`--portal-net 0.0.0.0/0`) a portál jelszavas védelme mellett.

Telepítés után állítsd be a klienseken:

- alapértelmezett átjáró: a kapu LAN-címe (`--gateway-ip`, alapból a LAN
  interfész címe),
- DNS: a kapu címe, ha dnsmasq-t használsz (lásd lentebb), különben a
  belépés előtt a DNS is akadályba ütközhet.

### Kézi telepítés (az installer nélkül)

```bash
# 1) Program és rendszerfelhasználó
sudo groupadd --system hatarvedelem 2>/dev/null || true
sudo useradd --system --home-dir /var/lib/hatarvedelem \
     --shell "$(command -v nologin || echo /bin/false)" \
     --gid hatarvedelem hatarvedelem
sudo install -d -m 0755 /opt/hatarvedelem
sudo install -m 0644 server.py gateway.py index.html icon.png services.json README.md /opt/hatarvedelem/
sudo install -d -m 0750 -o hatarvedelem -g hatarvedelem /var/lib/hatarvedelem

# 2) nftables-szabályok (a <...> helyekre a saját értékeid)
sudo install -d -m 0755 /etc/nftables
sed -e 's|__LAN_IF__|eth1|g' -e 's|__WAN_IF__|eth0|g' \
    -e 's|__LAN_NET__|192.168.50.0/24|g' \
    -e 's|__PORTAL_NET__|0.0.0.0/0|g' \
    -e 's|__PORT__|80|g' \
    deploy/hatarvedelem.nft | sudo tee /etc/nftables/hatarvedelem.nft >/dev/null
sudo chmod 0600 /etc/nftables/hatarvedelem.nft
sudo nft -c -f /etc/nftables/hatarvedelem.nft
sudo nft -f /etc/nftables/hatarvedelem.nft   # idempotens, ismételhető

# 3) IP-továbbítás
echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/90-hatarvedelem.conf >/dev/null
sudo sysctl -q -w net.ipv4.ip_forward=1

# 4) systemd unitok. A __PYTHON__ helyére a 3.8+ interpreter kerüljön
#    (RHEL 8-on /usr/bin/python3.9, máshol jellemzően /usr/bin/python3).
NFT="$(command -v nft)"
sed -e "s|__NFT_BIN__|$NFT|g" \
    deploy/hatarvedelem-firewall.service | \
  sudo tee /etc/systemd/system/hatarvedelem-firewall.service >/dev/null
sed -e "s|__PYTHON__|/usr/bin/python3|g" -e "s|__NFT_BIN__|$NFT|g" \
    -e 's|__PORT__|80|g' -e 's|__PORTAL_URL__|http://192.168.50.1|g' \
    deploy/hatarvedelem.service | \
  sudo tee /etc/systemd/system/hatarvedelem.service >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now hatarvedelem-firewall
sudo systemctl enable --now hatarvedelem

# 5) Első felhasználó:
sudo env HV_USERS=/var/lib/hatarvedelem/users.json \
  python3 /opt/hatarvedelem/server.py user add alice
sudo chown hatarvedelem:hatarvedelem /var/lib/hatarvedelem/users.json
sudo chown hatarvedelem:hatarvedelem /var/lib/hatarvedelem/users.json.lock 2>/dev/null || true
```

A `sed`-ekben a saját interfészeidet, hálózataidat és címedet írd. A
`deploy/hatarvedelem.nft`, a `deploy/hatarvedelem-firewall.service` és a
`deploy/hatarvedelem.service` a projekt `deploy/` könyvtárában van; élesben
az `/etc` alá kerülnek. A `hatarvedelem-firewall.service` a `sysinit.target`
része, ezért bootkor akkor is betölti a szabályokat, ha a `nftables.service`
nincs engedélyezve. A `nftables.service`-t nem kell (és nem is kell
átkonfigurálni) ehhez.

## Felhasználók kezelése

A felhasználók a `/var/lib/hatarvedelem/users.json` fájlban vannak
(PBKDF2-SHA256, felhasználónkénti só, 0600). A szolgáltatás futása közben is
szerkeszthető; a változás a következő belépésnél érvényesül. Dockerben a
fenti `docker compose run` parancsok használhatók; az alábbiak a bare-metal
telepítéshez valók. RHEL 8-on a lenti `python3` helyett `python3.9`-et
használj (a telepítő ezt választja a systemd unitban is).

A felhasználóknak két szerepkörük lehet:

- **`admin`** – belépés után az **Admin** fület is látja. Kezelheti a
  felhasználókat, csoportokat, szabályokat, és megtekintheti az auditnaplót.
  Az adminok mindig megkapják a beépített `admin-full` szabályt (teljes
  hozzáférés), így nem tudják magukat kizárni a portálról.
- **`user`** – kizárólag a neki engedélyezett szabályokat látja és
  választhatja. A szabályokat közvetlenül a felhasználóhoz vagy
  csoportokon keresztül kapja (a kettő uniója érvényes).

A felhasználók létrehozása, jelszavuk, szerepkörük, állapotuk (engedélyezett/
letiltott), közvetlen szabályaik és csoporttagságaik az admin felületről
kezelhetők. A CLI továbbra is hasznos vészhelyzeti eszköz, de csak `user`
szerepkört hoz létre, és nem állít be szabályokat.

Új felhasználó, admin általi jelszó-visszaállítás és CLI-s jelszóbeállítás
esetén a fiók **első belépésnél jelszócserére kényszerít**: amíg a
felhasználó nem ad meg új jelszót, a portál csak a jelszócsere-oldalt
mutatja, és az `/api/access`, valamint admin esetén az `/api/admin/*`
végpontok 403-mal elutasítanak. A jelszócsere a bejelentkezett munkamenetet
megtartja, a felhasználó többi (másik IP-ről indított) munkamenetét viszont
azonnal visszavonja. A tiltás és az admin általi jelszó-visszaállítás
szintén azonnal visszavon minden futó munkamenetet.

### Admin fiók Docker Compose-ból

A `.env` fájlban megadható egy induláskori admin fiók. Ha a
`HV_ADMIN_ENABLED=1`, a konténer indulásakor létrehozza a `HV_ADMIN_USER`
felhasználót `admin` szerepkörrel. Ha a fiók már létezik, a viselkedés a
`provisioned_from` mezőtől függ, amely azt jelzi, hogy a jelenlegi jelszó
a `.env`-ből származik-e:

- **A fiókot a felületről vagy CLI-vel hozták létre / a jelszót ott
  cserélték le:** az indulás nem nyúl a jelszóhoz, csak az `admin`
  szerepkört és az engedélyezett állapotot kényszeríti ki. A felületi
  jelszócsere tehát megmarad az újraindítás után is.
- **A `.env` jelszava megváltozott:** a konténer visszaállítja a jelszót az
  új `HV_ADMIN_PASSWORD` értékre, és ismét első belépésnél jelszócserére
  kényszerít.
- **Régi, marker nélküli fiók:** ha a `.env` jelszava még érvényes, a
  konténer felveszi a markert és bekapcsolja a kötelező jelszócserét; ha
  nem, visszaállítja a jelszót a `.env` értékére. Az első ilyen indulás
  után tehát az adminnak egyszer jelszót kell cserélnie.

Új admin fiók létrehozásakor a kezdetleges jelszó után szintén kötelező az
első belépésnél történő csere. Először generálj jelszót, majd illeszd be a
`.env`-be:

```bash
openssl rand -hex 16
```

```bash
HV_ADMIN_ENABLED=1
HV_ADMIN_USER=admin
HV_ADMIN_PASSWORD=<a generált jelszó>
```

A jelszó a `.env`-ben egyszerű szövegként áll, ezért a fájl jogosultsága
`0600` legyen. A `HV_ADMIN_ENABLED=0` az alapértelmezés: a portál nem nyúl a
felhasználókhoz, és a korábban létrehozott fiókot sem törli. A `.env`
jelszavának módosítása után a konténer újraindítása (`docker compose up -d`)
érvényesíti az új értéket, és az adminnak a következő belépésnél le kell
cserélnie. Ha a jelszót a portál felületén cserélted le, azt az újraindítás
nem írja felül.

Bare-metal telepítésnél ugyanezeket a változókat a systemd unit
`Environment=` soraiba vedd fel (a sablonban kommentben ott vannak), majd
`systemctl daemon-reload && systemctl restart hatarvedelem`. Az admin
fiókot a portál indulásakor hozza létre, `admin` szerepkörrel.

### Admin felület

Admin szerepkörű felhasználóval belépve a fejléc **Admin** füle hat
oldalt nyit:

- **Felhasználók** – létrehozás, szerkesztés, törlés; jelszó, szerepkör,
  engedélyezett/letiltott állapot; közvetlen szabályok és csoportok
  kiválasztása kereshető listából. A táblázat mutatja az érvényes
  szabályokat is. Az admin által megadott jelszó első belépésnél cserére
  kényszerít; a **Letiltás** és a jelszó-visszaállítás azonnal visszavonja
  a felhasználó futó munkameneteit.
- **Csoportok** – csoport létrehozása azonosítóval és leírással, a
  csoporthoz rendelhető szabályok és tagok kiválasztása kereshető listából.
  A tagság és a csoportszabályok módosítása az érintett felhasználók futó
  munkameneteit visszavonja.
- **Szabályok** – szabály létrehozása: azonosító, név, leírás, TCP- és
  UDP-portlista (vesszővel vagy szóközzel elválasztva), ICMP és teljes
  hozzáférés, valamint alapértelmezett és maximális idő. Egy szabály több
  portot is tartalmazhat; a portok 1–65535 közöttiek. A `admin-full`
  beépített szabály nem szerkeszthető és nem törölhető; minden admin
  automatikusan megkapja.
- **Munkamenetek** – a nyitott munkamenetek listája: felhasználó, IP,
  állapot (jóváhagyva / még nincs hozzáférés), szabály és portok, belépés
  ideje, hátralévő idő és az eszköz user-agentje. A hátralévő idő
  másodpercenként frissül, a lista öt másodpercenként. A soroknál a
  **Lezárás** azonnal bontja a kiválasztott munkamenet hozzáférését, a
  **Zárolás** pedig letiltja a felhasználót, és ezzel minden munkamenetét
  lezárja. A saját munkamenet lezárására a Kilépés gomb való. Az azonos
  IP-ről történő új bejelentkezés a korábbi munkamenetet lezárja (lásd
  lentebb).
- **Tűzfal** – a kernel tényleges állapota: az `allowed_v4`,
  `allowed_tcp`, `allowed_udp`, `allowed_icmp` és `host_ssh_v4` halmazok
  elemei IP-cím szerint csoportosítva. Minden kártya mutatja a nyitott
  TCP/UDP portokat, az ICMP-t és a host SSH-t, a portonkénti hátralévő
  időt, az aktív munkamenet felhasználóját, szabályát és portjait. A
  nézet összeveti a kernelt a munkamenetekkel: jelzi a hiányzó vagy
  váratlan portokat, a hiányzó host SSH-t, illetve az olyan IP-t, amelyhez
  már nincs munkamenet („nincs munkamenet”). A lista öt másodpercenként
  frissül, a visszaszámlálók másodpercenként. A nézet csak olvas, nem
  módosítja a tűzfalat.
- **Naplók** – az auditnapló szűrhető nézete eseményre, felhasználóra és
  szabad szövegre, 200–2000 soros limittel és opcionális öt másodperces
  automatikus frissítéssel. Minden sor mellett a teljes JSON-részlet is
  látható.

Egy IP-címről egyszerre csak **egy** munkamenet lehet aktív: ha ugyanarról
a címről (például NAT mögül, másik böngészőből) újra belép valaki, a
korábbi munkamenet azonnal lezárul, és a portál a lejárt munkamenet
helyén kiírja az okot („új belépés ugyanerről az IP-ről”). Ez magyarázza
a váratlan kiléptetést akkor is, ha a visszaszámláló még futott. A
nyilvános IP megváltozása (VPN ki-/bekapcsolása) szintén lezárja a
munkamenetet.

A szabályok és csoportok a `rules.json`, illetve `groups.json` fájlban
tárolódnak. Ezeket az admin felület kezeli; kézi szerkesztés helyett
használd a felületet, mert a változások így azonnal érvényesülnek és
bejegyzés kerül az auditnaplóba. Ha egy szabályt törölsz, a rá hivatkozó
felhasználói és csoport-hozzárendelések is törlődnek, a szabályra épülő
munkamenetek pedig azonnal visszavonódnak.

Az admin felület csak akkor jelenik meg, ha a bejelentkezett felhasználó
szerepköre `admin`. A szerver oldali végpontok (`/api/admin/*`) minden
más szerepkörnek 403-at adnak, tehát a fül elrejtése nem biztonsági
kontroll, csak kényelmi megoldás.

### Kezelőparancs a VM-en

A `deploy/hv` egy rövid bash-parancs, amely a projektkönyvtárból dolgozik, és
nem kell fejben tartani a compose és a konténer belső útvonalait. Telepítés
rootként:

```bash
install -m 0755 deploy/hv /usr/local/bin/hv
install -m 0644 deploy/HELYI-UTMUTATO.md /root/hatarvedelem/HELYI-UTMUTATO.md
```

Ezután:

```bash
hv status      # konténer, portál, nft halmazok
hv edit        # .env szerkesztése (utána hv restart)
hv services    # services.json szerkesztése (utána hv rebuild)
hv users       # felhasználók listája
hv add alice   # új felhasználó; jelszót interaktívan kér, első belépésnél cserélni kell
hv passwd alice
hv del alice
hv backup      # projekt + teljes állapot -> /root/hatarvedelem-backups
hv logs
hv restart     # .env újraolvasása
hv rebuild     # kód / services.json után
hv test        # unit- és HTTP-tesztek
hv e2e         # teljes teszt a hvclient névtérből
hv where       # a HELYI-UTMUTATO.md tartalma
```

A parancs feltételezi, hogy a projekt `/root/hatarvedelem` alatt van; más
telepítési helynél a script elején az `APP` változót kell átírni.

### Bare-metal CLI

```bash
# hozzáadás (jelszót interaktívan kér)
sudo env HV_USERS=/var/lib/hatarvedelem/users.json \
  python3 /opt/hatarvedelem/server.py user add alice

# jelszócsere
sudo env HV_USERS=/var/lib/hatarvedelem/users.json \
  python3 /opt/hatarvedelem/server.py user passwd alice

# törlés, lista
sudo env HV_USERS=/var/lib/hatarvedelem/users.json \
  python3 /opt/hatarvedelem/server.py user del alice
sudo env HV_USERS=/var/lib/hatarvedelem/users.json \
  python3 /opt/hatarvedelem/server.py user list
```

Automatizáláshoz a jelszó a szabványos bemenetről is jöhet (így nem kerül a
parancssorba, de a shell-előzménybe igen, ha `echo`-t használsz):

```bash
printf '%s\n' 'hosszu-jelszo' | sudo env HV_USERS=/var/lib/hatarvedelem/users.json \
  python3 /opt/hatarvedelem/server.py user add alice --password-stdin
```

A jelszó 8–1024 karakter. A felhasználónév 1–32 karakter: betű, szám, pont,
kötőjel, aláhúzás. A `user add` és a `user passwd` alapértelmezés szerint az
első belépésnél kötelező jelszócserét állít be; `--no-must-change`
kapcsolóval ez kihagyható (például automatizált tesztfiúknál). A portálon
keresztül végzett jelszócsere a bejelentkezett munkamenetet megtartja, a
felhasználó többi munkamenetét viszont visszavonja. A CLI-s jelszócsere
futó munkameneteket nem érint; azok a lejáratig érvényesek. Ha azonnal ki
akarsz zárni valakit, tiltsd le az admin felületen (ez azonnal visszavon
minden munkamenetet), vagy töröld a felhasználót és indítsd újra a
szolgáltatást.

## Beállítások

A szolgáltatás környezeti változókkal konfigurálható.

- **Docker:** a projekt mellett lévő `.env` fájlt szerkeszd, majd
  `docker compose up -d` (a változás új konténert indít; a portál
  újraindul, ezért mindenki kijelentkezik).
- **Bare-metal:** a systemd unitban
  (`/etc/systemd/system/hatarvedelem.service`) az `Environment=` sorokat
  szerkeszd, majd:

```bash
sudo systemctl daemon-reload && sudo systemctl restart hatarvedelem
```

| Változó | Alapértelmezés | Jelentés |
|---|---|---|
| `PORT` | Docker: `8100`; unit: `80` | a portál figyelő portja |
| `HV_STATE_DIR` | a projekt könyvtára; Docker: `/var/lib/hatarvedelem` | állapotkönyvtár |
| `HV_USERS` | `<HV_STATE_DIR>/users.json` | felhasználói adatbázis |
| `HV_RULES` | `<HV_STATE_DIR>/rules.json` | admin által kezelt hozzáférési szabályok |
| `HV_GROUPS` | `<HV_STATE_DIR>/groups.json` | csoportok, tagságok és csoportszabályok |
| `HV_AUDIT_LOG` | `<HV_STATE_DIR>/audit.jsonl` | JSONL auditnapló útvonala |
| `HV_AUDIT_MAX_BYTES` | `10485760` | napló rotálása ennél a méretnél (legalább 256 KiB) |
| `HV_AUDIT_KEEP` | `5` | megtartott rotált naplófájlok száma (1–20) |
| `HV_ADMIN_ENABLED` | `0` | induláskori admin fiók létrehozása/frissítése (`1`/`0`) |
| `HV_ADMIN_USER` | nincs | az admin fiók felhasználóneve (ha enabled) |
| `HV_ADMIN_PASSWORD` | nincs | az admin fiók jelszava (ha enabled; 8–1024 karakter) |
| `HV_LAN_IF`, `HV_WAN_IF` | nincs; Dockerben kötelező | a LAN/WAN interfész neve a szabálysablonhoz |
| `HV_LAN_NET` | nincs; Dockerben kötelező | a kliensek IPv4 hálózata CIDR formában |
| `HV_MGMT_NET` | nincs; a `HV_PORTAL_NET` alapértéke | már nem ad SSH-t; csak a portál forrásának alapértéke |
| `HV_PORTAL_NET` | a `HV_MGMT_NET` értéke | ahonnan a portál elérhető; `0.0.0.0/0` = nyilvános; a host SSH-t nem érinti |
| `HV_SERVICES_FILE` | `<programkönyvtár>/services.json` | a kezdő szabályokhoz és a régi, szolgáltatás-alapú `rules.json` átalakításához használt katalógus |
| `HV_SESSION_TTL` | `3600` | a TTL-mező kezdőértéke és a szabályok alapértelmezett TTL-je (másodperc) |
| `HV_MIN_TTL` | `60` | a választható idő alsó korlátja (legalább 60) |
| `HV_MAX_TTL` | `86400` | a választható idő felső korlátja (legfeljebb 86400) |
| `HV_AUTH_TTL` | `600` | a jelszavas belépés és a szabályválasztás között rendelkezésre álló idő |
| `HV_CHALLENGE_TTL` | `600` | a captcha-kihívás élettartama |
| `HV_POW_DIFFICULTY` | `4` | proof-of-work nehézség (ennyi vezető hex nulla kell; 1–6) |
| `HV_PBKDF2_ITERATIONS` | `600000` | új jelszavak PBKDF2-iterációi |
| `HV_RATE_WINDOW` | `60` | bejelentkezési időablak (másodperc) |
| `HV_RATE_MAX` | `10` | próbálkozások száma ablakonként, IP-nként |
| `HV_NFT_BIN` | automatikus | az `nft` bináris helye |
| `HV_NFT_TABLE` | `hatarvedelem` | nftables tábla neve |
| `HV_NFT_SET` | `allowed_v4` | a teljes hozzáférés halmazának neve |
| `HV_CONNTRACK_BIN` | automatikus | a `conntrack` bináris helye |
| `HV_DRY_RUN` | `0` | `1`: nem módosítja a tűzfalat, csak naplóz |
| `HV_FLUSH_ON_START` | `1` | induláskor kiüríti a dinamikus halmazokat |
| `HV_SKIP_FIREWALL` | `0` | Docker: `1` esetén a szabályok betöltése kimarad (csak hibakereséshez, nem biztonságos) |
| `HV_RUN_AS_ROOT` | `0` | Docker: `1` esetén a portál rootként fut setpriv helyett |
| `HV_PORTAL_URL` | üres | kanonikus portálcím; más Host esetén 302 oda |
| `HV_COOKIE_SECURE` | `0` | `1`: `Secure` süti (HTTPS-terminálás mögött) |
| `TURNSTILE_SITEKEY`, `TURNSTILE_SECRET` | üres | opcionális Cloudflare Turnstile |

A `HV_SESSION_TTL` a felület TTL-mezőjének kezdőértéke, illetve az új
szabályok alapértelmezett TTL-je. A felhasználó ettől eltérhet a szabály
`max_ttl` értékéig, de legfeljebb a `HV_MIN_TTL`–`HV_MAX_TTL` tartományon
belül; a szerver kemény korlátja 60–86400 másodperc (1 perc – 24 óra). A
kiválasztott érték lesz az nft-halmaz elemek kerneloldali timeoutja is,
így a munkamenet és a tűzfalengedély nem csúszhat el egymástól.

A felhasználó csak olyan szabályt kérhet, amelyre jogosult: a saját
közvetlen szabályai, a csoportjain keresztül kapott szabályok, illetve
admin esetén a beépített `admin-full` közül. A szabály portlistája
határozza meg, milyen portok nyílnak meg; a kliens nem tud a szabályon
kívüli portot kérni.

### Szolgáltatáskatalógus (kezdő szabályokhoz és migrációhoz)

A szabályok szerkesztése portalapú: az admin felületen TCP/UDP portokat,
ICMP-t vagy teljes hozzáférést adsz meg. A `services.json` ettől
függetlenül megmaradt két célra: a `scenarios` az **első induláskor**
létrehozza a kezdő szabályokat (amikor még nincs `rules.json`), a
`services` lista pedig a korábbi, szolgáltatás-alapú `rules.json`
automatikus portokra alakításához kell. Új szabályt már nem lehet
szolgáltatásból építeni; a portokat közvetlenül a szabály tartalmazza.

A `scenarios` minden eleme azonosítóval, névvel, leírással és
szolgáltatáslistával jön létre kezdő szabályként. A későbbi módosításokat
már az admin felület végzi; a `services.json` scenario-módosításai nem
írják felül a meglévő szabályokat. Ha az admin minden szabályt töröl, az
üres `rules.json` megmarad, és a szabályok nem jönnek létre újra a
következő indításnál. Egy régi, `services` mezőt tartalmazó `rules.json`
első betöltéskor biztonsági másolatot kap
(`rules.json.services-backup-<időbélyeg>`), majd port-alapú formátumban
íródik vissza. Ha a régi fájl hibás bejegyzést tartalmaz, az automatikus
átírás elmarad, és a hiba a naplóba kerül.

```json
{
  "services": [
    {"id": "web", "label": "Web", "description": "HTTP és HTTPS",
     "tcp": [80, 443], "udp": [443]},
    {"id": "icmp", "label": "Ping", "description": "ICMP echo", "icmp": true},
    {"id": "all", "label": "Teljes hozzáférés", "description": "Minden port",
     "all": true}
  ],
  "scenarios": [
    {"id": "browse", "label": "Böngészés", "description": "Web és DNS",
     "services": ["web", "dns"], "default_ttl": 3600, "default": true}
  ]
}
```

- `tcp` / `udp`: célportok listája (1–65535). A szabály a kliens IP-je és
  a **célport** párosára nyílik, nem a forrásportra.
- `icmp`: `true` esetén ICMP echo engedélyezett.
- `all`: `true` esetén a kliens a `allowed_v4` halmazba kerül, minden
  port és protokoll engedélyezett. Legfeljebb egy ilyen szolgáltatás lehet.
- A `default_ttl` másodpercben értendő; az ebből létrejövő kezdő szabály
  alapértelmezett TTL-je lesz, a szerver a `HV_MIN_TTL`–`HV_MAX_TTL`
  tartományba vágja.
- A `"default": true` csak visszafelé kompatibilis metaadatként maradt
  meg; a felület a mindenkori szabálylistát használja.
- A `scenarios` szolgáltatáslistájában csak létező `services` azonosító
  szerepelhet; ismeretlen szolgáltatásnál a katalógus betöltése hibát ad.
  A régi szabályok átalakításakor is ez a lista adja a portokat.

A fájl induláskor töltődik be; hiányzó vagy hibás katalógussal a portál
nem indul el (fail-closed). Új szolgáltatás hozzáadásához Dockerben újra
kell építeni a képet (`docker compose up -d --build`), bare-metalon a
szolgáltatást kell újraindítani. Ez csak a kezdő szabályokat és a régi
szabályok átalakítását érinti; a már létező, port-alapú szabályokat nem.

### Fejlesztés/try-out tűzfal nélkül

```bash
# előbb egy felhasználó ugyanabba az állapotkönyvtárba:
HV_USERS=/tmp/hv/users.json python3 server.py user add teszt

HV_DRY_RUN=1 HV_STATE_DIR=/tmp/hv PORT=8100 python3 server.py
```

Ilyenkor a belépés ugyanúgy ellenőrzi a jelszót, de az nft-parancsok csak a
naplóba kerülnek. A `HV_DRY_RUN=1` soha ne maradjon bekapcsolva éles gépen.

## A portál viselkedése

- A nem engedélyezett, LAN felől érkező HTTP (80-as port) forgalom a portálra
  kerül; a portál minden ismeretlen, nem `/api/` útvonalra az `index.html`-t
  adja vissza (az ismeretlen `/api/` végpontok 404-et adnak).
- A 80-tól eltérő `PORT` esetén a redirect a beállított portra mutat.
- Ha egy GET kérés `Host` fejlécje nem egyezik a `HV_PORTAL_URL` címével, a
  szerver 302-vel oda irányít, hogy a süti és az állapot egy helyen legyen.
- Belépés után a felület egyetlen, görgetésmentes hozzáférés-választót
  mutat: a felhasználó a számára elérhető szabályok közül választ egyet,
  és megadja az időtartamot percben vagy órában. A szabály kártyája mutatja
  a portokat, a leírást és a maximális TTL-t; a csúszka/mező efölé
  nem enged menni. A lábléc rögzített, csak a szabálylista görgethető, ha
  sok szabály van. A „Hozzáférés engedélyezése” gomb küldi a
  `POST /api/access` kérést `{"rule": "<id>", "ttl": <másodperc>}`
  formában. A választás a `HV_AUTH_TTL` ideig érvényes; utána újra be kell
  lépni.
- **Admin** szerepkörnél a lista élén a beépített `admin-full` szabály
  áll, és ez van előre kiválasztva. A `user` szerepkör csak a saját vagy
  csoportos szabályait látja; ha egyik sincs, a felület jelzi, hogy
  hozzáféréshez adminnak kell szabályt rendelnie.
- Engedélyezés után a munkamenet-nézet mutatja a kiválasztott szabályt,
  annak portjait és a hátralévő időt. A „Hozzáférés módosítása”
  gomb visszaviszi a választóhoz; a mentés a régi engedélyeket
  visszavonja, majd az újakat állítja be. A „Vissza az előző oldalra” gomb
  a böngésző előzményeit használja.
- Admin belépésnél a fejléc **Admin** füle hatoldalas kezelőfelületet
  nyit (felhasználók, csoportok, szabályok, munkamenetek, tűzfal,
  naplók). A naplónézet szűrhető, és öt másodpercenként frissülhet; a
  részletes események JSON-formában is megjeleníthetők.
- **HTTPS:** belépés előtt a böngésző HTTPS-kérése nem irányítható át
  tanúsítvány-hiba nélkül. A felhasználónak a portál HTTP-címét kell
  megnyitnia. Belépés után a HTTPS már a megszokott módon működik.
- **DNS:** a tűzfal a kapu felé engedi a DNS-t (53), hogy a dnsmasq
  kiszolgálhassa a klienseket. A dnsmasq a saját upstreamjére továbbít, így
  belépés előtt is lehet DNS-választ kapni — ez a portál használhatóságának
  ára. Ha ezt nem szeretnéd, ne futtass dnsmasq-t, és a kliensek a belépés
  előtt IP-címet használjanak.
- A portál automatikus captive-portal felugrása nem minden operációs
  rendszeren garantált; a cím (`http://<kapu-ip>/`) kézzel is megnyitható.

### DHCP/DNS (opcionális)

```bash
# Telepítsd a disztribúciód csomagkezelőjével, például:
#   sudo dnf install -y dnsmasq        (RHEL/Fedora)
#   sudo apt-get install -y dnsmasq    (Debian/Ubuntu)
#   sudo zypper install -y dnsmasq     (SUSE)
sudo install -m 0644 deploy/dnsmasq-hatarvedelem.conf /etc/dnsmasq.d/hatarvedelem.conf
# szerkeszd a helyőrzőket: __LAN_IF__, __DHCP_START__, __DHCP_END__, __GW_IP__
sudo systemctl enable --now dnsmasq
```

A mellékelt tűzfal-szabály már engedi a LAN felől az 53/67-es portot a kapun.
A dnsmasq nem települ automatikusan.

## Biztonsági jegyzetek

- **Jelszavak:** PBKDF2-HMAC-SHA256, felhasználónkénti 16 bájtos só,
  `hmac.compare_digest`, ismeretlen felhasználónál is dummy hash (időzítés-
  oldali csatorna ellen). Az új jelszavak a `HV_PBKDF2_ITERATIONS` értékkel
  készülnek; a régi hashek a saját iterációszámukkal ellenőrződnek.
- **Captcha:** a szerver HMAC-kulccsal aláírt, egyszer használható
  proof-of-work kihívást ad; a böngésző a választ csak a jelszóval együtt
  küldi. A kihívás lejár, és nem használható újra. A Turnstile opcionális,
  de a kliensnek belépés előtt el kell érnie a Cloudflare-t, amit a tűzfal
  alapból nem enged — éles használatához külön kivétel kell.
- **Munkamenet:** memóriabeli, véletlen token, IP-hez kötve. A jelszó
  ellenőrzése csak függő (pending) munkamenetet hoz létre, amelyhez nem
  tartozik tűzfalengedély; a hálózat csak a szabály- és TTL-választás
  (`POST /api/access`) után nyílik meg. A szerver minden kérésnél
  ellenőrzi, hogy a szabály szerepel-e a felhasználó érvényes
  szabálykészletében. A süti `HttpOnly`, `SameSite=Lax`;
  `Secure` csak `HV_COOKIE_SECURE=1` esetén. A token más IP-ről nem
  használható.
- **CSRF:** `SameSite=Lax` + `Origin`/`Host` ellenőrzés a POST kéréseken.
- **Rate limit:** IP-nként 10 bejelentkezési kísérlet percenként; efelett
  429 és `Retry-After`.
- **Fájlkiszolgálás:** csak az `index.html` és az `icon.png` érhető el. A
  `server.py`, `gateway.py`, `users.json`, `rules.json`, `groups.json`,
  `audit.jsonl` és a `.env` soha nem kerül kiszolgálásra; minden más
  nem-API GET az indexre esik vissza.
- **Admin jogosultság:** az admin végpontok szerveroldalon ellenőrzik a
  munkamenet szerepkörét; a pusztán rejtett felületi fül nem jelent
  védelmet. Az utolsó aktív admin nem tiltható le és nem törölhető, a
  beépített `admin-full` szabály nem törölhető, és minden admin
  automatikusan megkapja, így az admin nem zárhatja ki magát.
- **Auditnapló:** minden lényeges esemény (portál megnyitása, sikeres és
  sikertelen belépés, szabály kiválasztása, hozzáférés engedélyezése,
  módosítása, visszavonása, kilépés, lejárat, admin-műveletek és
  elutasított admin-kérések) időbélyeggel, felhasználóval, kliens-IP-vel
  és user agenttel együtt JSONL-fájlba kerül. A napló nem tartalmaz
  jelszót vagy hash-t, 0600 jogosultsággal készül, és méret alapján
  rotálódik. A naplózási hiba nem akasztja meg a belépést.
- **Jogosultságok:** a portál-szolgáltatás nem rootként fut, csak
  `CAP_NET_ADMIN` és `CAP_NET_BIND_SERVICE` képességgel; systemd-hardening
  (`ProtectSystem=strict`, `PrivateTmp`, `RestrictAddressFamilies`,
  `NoNewPrivileges` stb.). A `hatarvedelem-firewall.service` rootként, de
  csak `CAP_NET_ADMIN` képességgel tölti be a szabályokat.
- **Jogosultságok (Docker):** a konténer gyökérfájlrendszere csak olvasható.
  A belépési pont rootként tölti be a szabályokat, majd a portál a
  `hatarvedelem` felhasználóként, kizárólag `CAP_NET_ADMIN` és
  `CAP_NET_BIND_SERVICE` ambient képességgel fut. A `cap_drop: ALL` után a
  konténer csak a szükséges képességeket kapja vissza; a `CHOWN`,
  `DAC_OVERRIDE`, `FOWNER`, `SETUID`, `SETGID` kizárólag a belépési pont
  kötetjogosultság-kezeléséhez és felhasználóváltásához kell. A
  `no-new-privileges` be van kapcsolva, a `/run` és `/tmp` tmpfs.
- **Fail-closed:** nincs hozzáférés, ha a tűzfal frissítése nem sikerült; a
  hiba 503-mal jön vissza. Engedélyezéskor a szerver előbb törli a régi
  elemeket, majd egyetlen nft-szkripttel adja hozzá az újakat; ha a
  szkript hibát ad, minden részleges engedélyt visszavon, és a munkamenet
  függő állapotban marad.
- **Lejárat:** a kerneloldali timeout akkor is érvényesül, ha a szerver
  összeomlik. A visszajövő forgalom a `ct state established,related`
  szabályok miatt nem marad életben egy visszavont IP-nél; a
  `conntrack -D` ezt azonnal is megszünteti.
- **Nyilvános portál:** ha a `HV_PORTAL_NET=0.0.0.0/0`, a belépőoldal az
  internetről is elérhető. Ez nem nyit hálózati továbbítást: az továbbra
  is csak sikeres jelszó + szabályválasztás után jön létre. A
  jelszókitalálgatás ellen proof-of-work captcha és IP-nkénti rate limit
  véd. Éles, nyilvános használatnál terminálj TLS-t (reverse proxy vagy
  VPN) a portál elé, és állítsd be a `HV_COOKIE_SECURE=1` értéket.
- **Host SSH:** a 22-es port a hoston csak az engedélyezett portál-
  munkamenet forrás-IP-jéről érhető el. A `HV_MGMT_NET` ehhez már nem
  ad kivételt. A munkamenet lejártával a kernel-timeout, kilépéskor a
  `conntrack -D` zárja le a meglévő kapcsolatot is.
- **Indulás:** a `hatarvedelem-boot.service` a konténer indulása előtt a
  forward-láncot és a host SSH-t is eldobja; a portál a végleges szabályok
  betöltése után veszi át a helyét. A dinamikus halmazok
  (`HV_FLUSH_ON_START=1`) minden indulásnál kiürülnek, így senki nem marad
  belépve egy újraindítás után.
- **Idempotens szabályfájl:** a `hatarvedelem-firewall.service` újratöltése
  (`systemctl reload hatarvedelem-firewall`) nem duplázza a szabályokat, és
  nem törli a belépett kliensek halmazelemeit. A portál újraindítása ezzel
  szemben mindenkit kiléptet (`HV_FLUSH_ON_START=1`).
- **Ismert korlátok:** a belépőoldal HTTP-n, titkosítás nélkül megy a LAN-on
  (a jelszó a helyi hálózaton olvasható); több kliens egy NAT-olt IP mögött
  közös engedélyt kap; MAC-csalás egy engedélyezett IP-t eltéríthet; az IPv6
  továbbítás nincs engedélyezve (a forward policy drop minden IPv6-ot tilt);
  nincs felhasználónkénti sávszélesség- vagy forgalomszabály. Ha a LAN nem
  megbízható, terminálj TLS-t a portál elé, és állítsd be a
  `HV_COOKIE_SECURE=1` értéket.

## Hibakeresés

### Docker

```bash
# állapot, naplók, healthcheck
docker compose ps
docker compose logs -f hatarvedelem

# kik vannak éppen engedélyezve (timeouttal együtt)
docker compose exec hatarvedelem nft list sets inet hatarvedelem
docker compose exec hatarvedelem nft list set inet hatarvedelem allowed_tcp
docker compose exec hatarvedelem nft list set inet hatarvedelem host_ssh_v4

# a kapu saját tűzfal-ellenőrzése
docker compose exec hatarvedelem \
  python3 /opt/hatarvedelem/server.py check-firewall

# a konténer valóban host-hálózatban fut-e?
docker inspect --format '{{.HostConfig.NetworkMode}}' \
  "$(docker compose ps -q hatarvedelem)"
```

- **A konténer azonnal kilép:** `docker compose logs hatarvedelem`. A
  leggyakoribb ok a hiányzó `HV_LAN_IF`/`HV_WAN_IF`/`HV_LAN_NET`/
  `HV_PORTAL_NET`, vagy érvénytelen CIDR. A hibaüzenet megnevezi a
  változót. A `HV_MGMT_NET` csak akkor kell, ha a `HV_PORTAL_NET` üres.
- **A belépőoldal nem érhető el:** a `HostConfig.NetworkMode` legyen
  `host`. Bridge módban a szabályok csak a konténer saját névterére
  vonatkoznak. Ellenőrizd, hogy a kliens átjárója a VM, és hogy a
  `PORT` egyezik a redirectben használttal.
- **A belépés 503:** a portál nem éri el az nft-t vagy nincs
  `CAP_NET_ADMIN` képessége. A compose-ban maradjon benne a `NET_ADMIN`.
- **Belépés után sem megy a net:** a hoston `sysctl net.ipv4.ip_forward`
  legyen `1`; a kliens IP-je és a kiválasztott célport jelenjen meg a
  megfelelő halmazban (`allowed_v4`, `allowed_tcp`, `allowed_udp`,
  `allowed_icmp`); a `HV_WAN_IF` és a `HV_LAN_NET` egyezzen a tényleges
  topológiával. Dockerben ellenőrizd a
  `DOCKER-USER` láncot is: `sudo iptables -S DOCKER-USER` mutassa a két
  `hv-docker-fwd-*` szabályt. Ha hiányoznak, a Docker nem nft-alapú
  iptables-t használ, vagy a lánc később jött létre; indítsd újra a
  konténert (`docker compose up -d`).
- **A 8100-as port foglalt:** állítsd át a `PORT`-ot a `.env`-ben, majd
  `docker compose up -d`. A redirect és az input-szabály is ezt a portot
  használja.
- **Mindenki kijelentkezik újraindítás után:** szándékos
  (`HV_FLUSH_ON_START=1`); a `users.json` megmarad a kötetben.
- **Leállítás után is tiltva van a forward:** az nftables-tábla a host
  névterében marad. Ez fail-closed viselkedés; eltávolítása:
  `sudo nft delete table inet hatarvedelem`.

### Bare-metal

```bash
# szolgáltatások és naplók
sudo systemctl status hatarvedelem hatarvedelem-firewall
sudo journalctl -u hatarvedelem -f
sudo journalctl -u hatarvedelem-firewall -f

# kik vannak éppen engedélyezve (timeouttal együtt)
sudo nft list sets inet hatarvedelem
sudo nft list set inet hatarvedelem allowed_tcp

# a szabályok ellenőrzése és idempotens újratöltése
sudo nft -c -f /etc/nftables/hatarvedelem.nft
sudo systemctl reload hatarvedelem-firewall

# a kapu saját tűzfal-ellenőrzése
sudo env HV_NFT_TABLE=hatarvedelem HV_NFT_SET=allowed_v4 \
  python3 /opt/hatarvedelem/server.py check-firewall

# conntrack
sudo conntrack -L -s 192.168.50.23

# portfoglalás
sudo ss -ltnp | grep -E ':80|:8100'
```

- **A belépés 503-at ad:** az nft nem érhető el vagy nincs `CAP_NET_ADMIN`.
  Aktív-e a `hatarvedelem-firewall.service`? Létezik mind a négy dinamikus
  halmaz (`allowed_v4`, `allowed_tcp`, `allowed_udp`, `allowed_icmp`)?
  Rootként működik-e a `check-firewall`?
- **A portál nem jön be:** a kliens átjárója a kapu? A `forward` és
  `prerouting` szabályok betöltődtek (`nft list ruleset`)? A 80-as portot
  nem foglalja más? A `PORT` egyezik a redirectben használttal? WAN felől
  csak `HV_PORTAL_NET=0.0.0.0/0` esetén érhető el.
- **Belépés után sem megy a net:** `ip_forward` be van kapcsolva? A kliens
  IP-je és a kiválasztott célport megjelenik a megfelelő halmazban? A NAT
  (`masquerade`) a WAN interfészre és a LAN hálózatra szól? A kliens DNS-e
  működik? Ha csak bizonyos portok mennek, ellenőrizd az admin **Szabályok**
  fülén a szabály portlistáját, illetve a **Tűzfal** nézetben a kernelben
  ténylegesen nyitott portokat.
- **A szabályok nem töltődtek be bootkor:** `systemctl status
  hatarvedelem-firewall`. A unit a `sysinit.target` része, és ha van
  `nftables.service`, az után fut. Egy másik nftables-tábla azonos hookon
  ütközhet; ellenőrizd: `nft list ruleset`.
- **SELinux:** `ausearch -m avc -ts recent`; az installer `restorecon`-t
  futtat, de kézi másolásnál lehet, hogy kell.
- **firewalld / ufw / iptables-persistent:** ha közben visszakapcsoltad,
  ütközhet; kapcsold ki, vagy alakítsd át a szabályokat.
- **Mindenki kijelentkezik a portál újraindítása után:** ez szándékos
  (`HV_FLUSH_ON_START=1`). Ha meg akarod tartani a halmazt, állítsd `0`-ra,
  de akkor a lejárt elemek a kernel timeoutjáig megmaradhatnak. A
  `hatarvedelem-firewall` újratöltése ezzel szemben megőrzi a halmazt.

## Eltávolítás

### Docker

```bash
docker compose down          # a hatarvedelem-state kötet megmarad
# docker compose down -v     # ezzel a felhasználók is törlődnek

# a szabályok a host névterében maradnak; ez megnyitja a forwardot:
sudo nft delete table inet hatarvedelem

# a Docker forward-áthidaló szabályainak eltávolítása (a LAN interfész nevével)
sudo iptables -D DOCKER-USER -i <LAN_IF> -m comment --comment hv-docker-fwd-in -j ACCEPT 2>/dev/null || true
sudo iptables -D DOCKER-USER -o <LAN_IF> -m comment --comment hv-docker-fwd-out -j ACCEPT 2>/dev/null || true
# ha korábban más interfésznév volt beállítva, az iptables -S DOCKER-USER
# listában keresd meg a régi hv-docker-fwd-* szabályokat is

# korai boot-védelem eltávolítása
sudo systemctl disable --now hatarvedelem-boot
sudo nft delete table inet hatarvedelem_boot 2>/dev/null || true
sudo rm -f /etc/systemd/system/hatarvedelem-boot.service \
           /etc/nftables/hatarvedelem-boot.nft
sudo systemctl daemon-reload

# ha másnak nem kell:
sudo rm -f /etc/sysctl.d/90-hatarvedelem.conf
sudo sysctl -q -w net.ipv4.ip_forward=0
```

A `docker compose down` önmagában **nem** nyitja meg a forward-láncot; a
tábla törlése tudatos művelet. Ha a boot-unit megmarad, a következő
indításkor ismét tiltani fog.

### Bare-metal (systemd)

```bash
sudo systemctl disable --now hatarvedelem
sudo systemctl disable --now hatarvedelem-firewall
sudo rm -f /etc/systemd/system/hatarvedelem.service \
           /etc/systemd/system/hatarvedelem-firewall.service
sudo systemctl daemon-reload

# A szabályok a szolgáltatás leállításakor is megmaradnak (nincs ExecStop),
# ezért a táblát külön kell törölni:
sudo nft delete table inet hatarvedelem
sudo rm -f /etc/nftables/hatarvedelem.nft /etc/sysctl.d/90-hatarvedelem.conf

# Régi (RHEL-es) telepítésnél az include sor is ott lehet; távolítsd el,
# különben az nftables.service a hiányzó fájlra hivatkozik:
# sudo sed -i '\|hatarvedelem.nft|d' /etc/sysconfig/nftables.conf

sudo rm -rf /opt/hatarvedelem /var/lib/hatarvedelem
sudo userdel hatarvedelem 2>/dev/null || true
sudo groupdel hatarvedelem 2>/dev/null || true
```

A tábla törlése **megnyitja** a továbbítást; ha kell, kapcsold vissza a
firewalld-t/ufw-t, vagy tölts be más szabályokat. Az `ip_forward` beállítás
megmarad; ha másnak nem kell, állítsd vissza:

```bash
sudo sysctl -q -w net.ipv4.ip_forward=0
```

## Tesztek

```bash
python3 -m unittest discover -s tests -v
```

A tesztek hamis `nft`/`conntrack` parancsokat használnak, nem nyúlnak a host
tűzfalához, és nem igényelnek rootot. A jelenlegi csomag 90 tesztet
tartalmaz. Lefedik a parancsépítést, a port-alapú szabálymodellt és a régi
szolgáltatás-alapú fájl migrációját, a TTL-korlátokat, a szabálytárat
(CRUD, beépített `admin-full`, kezdő szabályok seedelése csak hiányzó
fájlnál), a csoportokat és a szabályok feloldását (közvetlen + csoport +
admin), a kétfázisú munkamenet-kezelést (pending → authorize →
logout/lejárat), a captcha-visszajátszást, a rate limitet, a tűzfal-nézet
JSON-feldolgozását és a munkamenet–kernel összevetést, valamint a HTTP-s
végpontokat (belépés, `/api/access`, kilépés, IP-kötés, origin-ellenőrzés,
statikus fájlok kiszolgálásának tiltása) és az admin API-t
(jogosultságellenőrzés, felhasználó/csoport/szabály műveletek, utolsó
admin védelme, auditnapló).

A VM-en a valódi nftables-t és a `hvclient` hálózati névteret használó
végponttól végpontig teszt is futtatható. Ideiglenes felhasználót hoz létre,
majd töröl; a belépést, a szabályválasztást, a TTL-határokat, a
módosítást, a kilépést és a természetes lejáratot is ellenőrzi:

```bash
sudo python3 tests/e2e_vm.py
```

## Fájlok

| Fájl | Szerep |
|---|---|
| `gateway.py` | tűzfal, felhasználók, szabályok, csoportok, auditnapló, munkamenetek, captcha, konfiguráció |
| `server.py` | HTTP-szerver, nyilvános és admin végpontok, CLI (`serve`, `user`, `check-firewall`) |
| `index.html` | a portál felülete (egyoldalas hozzáférés-választó, admin panel, beépített SHA-256 proof-of-work, magyar UI) |
| `services.json` | kezdő szabályokat adó scenario-leírások és a régi szabályok portosításához használt katalógus |
| `deploy/hatarvedelem.nft` | idempotens nftables-sablon helyőrzőkkel |
| `deploy/hatarvedelem-firewall.service` | korán induló, szabálybetöltő unit (bare-metal) |
| `deploy/hatarvedelem.service` | a portál systemd unit-sablonja (bare-metal) |
| `deploy/hatarvedelem-boot.nft` | korai forward-tiltás a Docker indulása előtt |
| `deploy/hatarvedelem-boot.service` | a boot-táblát betöltő systemd unit |
| `deploy/dnsmasq-hatarvedelem.conf` | opcionális DHCP/DNS példa |
| `deploy/hv` | a VM-en `/usr/local/bin/hv` néven telepíthető kezelőparancs |
| `deploy/HELYI-UTMUTATO.md` | „hol mit szerkessz” útmutató (a `hv where` mutatja) |
| `Dockerfile` | a konténerkép (Debian slim, nftables, conntrack) |
| `docker-compose.yml` | host-hálózatos compose konfiguráció |
| `.env.example` | a Dockeres telepítés mintakonfigurációja |
| `.dockerignore` | a képbe nem kerülő fájlok (tesztek, állapot, .env) |
| `docker/entrypoint.sh` | sablonkitöltés, szabálybetöltés, jogosultságváltás |
| `docker/setup-host.sh` | host előkészítése a boot-védelemhez |
| `install.sh` | bare-metal telepítő |
| `tests/test_gateway.py` | unit- és HTTP-integrációs tesztek |
| `tests/e2e_vm.py` | végponttól végpontig teszt a VM-en valódi nftables-szel |
