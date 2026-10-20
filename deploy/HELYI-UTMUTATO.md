# Hol mit szerkessz

A projekt itt van: `/root/hatarvedelem`. A legtöbbször **két fájlhoz** kell
nyúlni. Mindenhez van rövid parancs, nem kell a Docker mappáiban keresgélni.

## Gyors parancsok

```bash
hv status      # fut-e a konténer, megy-e a portál, mi van az nft halmazokban
hv logs        # naplók élőben (Ctrl+C kilép)
hv restart     # újraindítás, hogy a .env új értékei érvénybe lépjenek
hv rebuild     # újraépítés, ha a kód vagy a kezdő szabályokat adó services.json változott
hv where       # ez a lap
```

## 1. Beállítások — `.env`

```bash
hv edit        # nano-val nyílik; utána: hv restart
```

Itt vannak a hálózati interfészek, a portál portja, az admin fiók, a TTL és a
proof-of-work nehézség. A fájl jogosultsága `0600`, mert az admin jelszó
egyszerű szövegként szerepel benne.

A leggyakoribb sorok:

| Sor | Mit jelent |
|---|---|
| `HV_LAN_IF` / `HV_WAN_IF` | belső és külső interfész neve (`ip -br link`) |
| `HV_LAN_NET` | a kiszolgált belső hálózat |
| `HV_PORTAL_NET` | erről a hálózatról érhető el a portál; `0.0.0.0/0` = bárhonnan |
| `HV_MGMT_NET` | már csak a `HV_PORTAL_NET` alapértéke; SSH-t nem engedélyez |
| `PORT` | a portál portja a hoston (a 80-as port ide irányít) |
| `HV_ADMIN_ENABLED` | `1`: induláskor létrehozza/frissíti az admin fiókot |
| `HV_ADMIN_USER` / `HV_ADMIN_PASSWORD` | az admin fiók adatai |
| `HV_SESSION_TTL` | a felhasználó által választható idő kezdőértéke |
| `HV_AUDIT_MAX_BYTES` / `HV_AUDIT_KEEP` | az auditnapló rotálásának mérete és megtartott fájljai |

**Admin jelszó csere:** `hv edit`, majd `hv restart`. A `.env` jelszavának
megváltoztatása visszaállítja az admin jelszavát, és a következő belépésnél
kötelező cserét ír elő. Ha a jelszót a portálon cserélted le, az az
újraindítás után is megmarad. A `HV_ADMIN_ENABLED=0` nem törli a fiókot,
csak nem foglalkozik vele. A többi felhasználót, csoportot és hozzáférési
szabályt a portál **Admin** paneljén kezeld.

## SSH a hostra

A host SSH (22-es port) **csak akkor** nyílik meg, ha a portálon
ugyanarról az IP-címről beléptél, és a portálon a beépített
**admin-full** szabályt engedélyezted (a TTL megadásával). Egyedi teljes
hozzáférésű vagy gyűjtőszabály nem nyitja meg. A jelszó
megadása önmagában még nem nyitja meg. Kilépéskor azonnal,
lejáratkor a kernel-timeouttal zárul. A böngésző és az SSH ugyanarról a
hálózatról induljon (VPN-nél ugyanaz az exit IP).

Ha kizártad magad, a szolgáltatói konzolról ideiglenesen vedd fel a
`deploy/hatarvedelem.nft` input láncában a kommentben jelzett sort, töltsd
újra a szabályokat, majd utána távolítsd el.

## 2. Szolgáltatáskatalógus — `services.json`

```bash
hv services    # szerkesztés; utána: hv rebuild
```

A szabályok már **port-alapúak**: az admin felületen TCP/UDP portokat,
ICMP-t vagy teljes hozzáférést adsz meg, egy szabály több portot is
tartalmazhat. A `services.json` csak két dolgot szolgál: a `scenarios`
az **első induláskor** hozza létre a kezdő szabályokat (amikor még nincs
`rules.json`), a `services` lista pedig a korábbi, szolgáltatás-alapú
`rules.json` automatikus portosításához kell. A későbbi szabályokat az
**Admin → Szabályok** oldalon kell kezelni. A fájlt a Dockerfile másolja
a konténerbe, ezért kell utána `hv rebuild`.

## Felhasználók, csoportok, szabályok

Az elsődleges felület az **Admin** panel a portálon. Ott hozhatók létre a
felhasználók, állítható a szerepkör (`admin`/`user`) és az engedélyezett
állapot, rendelhetők közvetlen szabályok és csoportok, valamint kezelhetők
a csoportok és szabályok. A szabályok, csoportok és tagok kiválasztása
kereshető listában történik (nincs sok kis jelölőnégyzet). A **Szabályok**
űrlapon a TCP- és UDP-portokat vesszővel vagy szóközzel elválasztva kell
megadni; egy szabály több portot is tartalmazhat, és adhat ICMP-t vagy
teljes hozzáférést. Docker által publikált konténerhez a host portját kell
beírni. Az időtartam a portálon percben vagy órában adható meg.

A **Naplók** fülön minden esemény szűrhető, a **Munkamenetek** fülön
pedig a nyitott munkamenetek és a hátralévő idő látható; ott a
**Lezárás** azonnal bont egy munkamenetet, a **Zárolás** pedig letiltja
a felhasználót és lezárja minden munkamenetét. A **Tűzfal** fül a kernel
tényleges állapotát mutatja IP-cím szerint csoportosítva: a nyitott
TCP/UDP portokat, ICMP-t és host SSH-t, a portonkénti hátralévő időt,
valamint a munkamenetekkel való egyezést (hiányzó/váratlan port, illetve
munkamenet nélküli kernelbejegyzés). A nézet csak olvas.

Az admin által megadott vagy visszaállított jelszót a felhasználó első
belépésnél köteles lecserélni. A letiltás és a jelszó-visszaállítás
azonnal lezárja a felhasználó futó munkameneteit. Egy IP-ről egyszerre
csak egy munkamenet aktív: az azonos IP-ről induló új belépés lezárja a
korábbit.

Vészhelyzeti CLI (csak `user` szerepkört hoz létre, szabályt nem rendel):

```bash
hv users           # lista
hv add alice       # új felhasználó, a jelszót kéri; első belépésnél csere
hv passwd alice    # jelszócsere; első belépésnél csere
hv del alice       # törlés
```

A kötelező első belépéskori csere kikapcsolható: `hv add alice --no-must-change`,
illetve `hv passwd alice --no-must-change`.

Az állapot a Docker volume-ban van
(`/var/lib/docker/volumes/hatarvedelem_hatarvedelem-state/_data/`):
`users.json`, `rules.json`, `groups.json`, `audit.jsonl` (és rotált
változatai). Ezeket **ne** szerkeszd kézzel — a felület és a CLI kezelik.
A fájlok 0600 jogosultságúak.

## Mentés és visszaállítás

```bash
hv backup          # projekt + teljes állapot ide: /root/hatarvedelem-backups
```

Két archívum készül: a projekt (`hatarvedelem-*.tar.gz`, a `.env`-vel
együtt) és a teljes állapot (`hatarvedelem-state-*.tar.gz`: felhasználók,
szabályok, csoportok, auditnapló). A mappa `0700`, a fájlok `0600`.
Visszaállításnál állítsd le a konténert, csomagold ki a projektarchívumot
`/root` alá, az állapotarchívumot pedig a
`/var/lib/docker/volumes/hatarvedelem_hatarvedelem-state/_data/` könyvtárba,
majd `hv restart`.

## Tesztek

```bash
hv test       # gyors unit-/HTTP-tesztek (a konténeren kívül)
hv e2e        # teljes végponttól végpontig teszt a hvclient névtérből
```

Az e2e a `hv-lan` veth párra és a `hvclient` névtérre épül; kb. 2 perc, és
ideiglenesen létrehoz egy `claudetest` felhasználót, amelyet a végén töröl.

## Fontos helyek

| Útvonal | Mi van ott |
|---|---|
| `/root/hatarvedelem/.env` | az élő beállítások (ne legyen világolvasható) |
| `/root/hatarvedelem/services.json` | kezdő szabályokat adó scenario-leírások és a régi szabályok portosításához használt katalógus |
| `/root/hatarvedelem/README.md` | részletes leírás, üzemeltetés, hibakeresés |
| `/root/hatarvedelem/deploy/hatarvedelem.nft` | az nftables sablon |
| `/root/hatarvedelem-backups/` | mentések |
| `/etc/systemd/system/hatarvedelem-boot.service` | boot védelem (fail-closed indulás) |
| `/var/lib/docker/volumes/hatarvedelem_hatarvedelem-state/_data/` | felhasználók, szabályok, csoportok, auditnapló |

## Ha valami nem megy

1. `hv status` — fut-e a konténer, válaszol-e a portál.
2. `hv logs` — a portál és az nft betöltés naplója.
3. `hv restart` — a `.env` újraolvasása.
4. Ha a kód vagy a kezdő szabályokat adó `services.json` változott: `hv rebuild`.
5. Visszaállítás: `hv backup`-ból kiválasztott archívum kibontása, majd `hv restart`.
