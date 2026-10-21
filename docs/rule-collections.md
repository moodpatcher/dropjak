# Gyűjtőszabályok és szabályduplikálás

A Dropjak admin felületén a szabályok mellett két kiegészítő művelet érhető
el:

- **Duplikálás** – bármely szabály (egyedi vagy gyűjtő) másolása egy
  kattintással; a fenntartott, régi azonosító kivétel.
- **Gyűjtőszabály** – több meglévő egyedi szabály összevonása egyetlen
  választható hozzáférési szabállyá.

A gyűjtőszabály ugyanúgy rendelhető felhasználóhoz vagy csoporthoz, mint
bármely más szabály, és a belépőoldalon egyetlen hozzáférési lehetőségként
jelenik meg.

## Szemantika

A gyűjtőszabály nem tárol saját portokat és **nincs saját iránya** sem. A
TCP-, UDP- és ICMP-jogosultsága a tagjai jogosultságainak **uniója**:

- TCP-portok: a tagok TCP-portjainak egyesítése.
- UDP-portok: a tagok UDP-portjainak egyesítése.
- ICMP: engedélyezett, ha bármelyik tag engedélyezi.
- Teljes hozzáférés: a gyűjtő soha nem adhat teljes hozzáférést, és teljes
  hozzáférésű szabály nem lehet a tagja.
- Irány (`direction`): minden tag a **saját irányában** kap engedélyt. A
  forward tagok portjai a forward halmazokba, a host (`input`) tagok portjai
  az `allowed_input_*` halmazokba kerülnek. Egy gyűjtő tagjai ezért vegyes
  irányúak is lehetnek; a feloldott gyűjtő megjelenítési iránya ilyenkor
  `mixed` (csak megjelenítési/audit érték, a tűzfal-műveletek irányonként
  külön `Ports` részekkel dolgoznak). A tag iránya akkor is módosítható,
  amikor már tagja egy gyűjtőnek; a függő gyűjtők munkamenetei ilyenkor
  visszavonásra kerülnek.

A gyűjtő saját `default_ttl` és `max_ttl` értékkel rendelkezik; a belépéskor
választott időtartam ezekhez igazodik, nem a tagok TTL-jeihez. A feloldott
portlista a felület minden helyén a megszokott `ports_label` mezőben
jelenik meg, a gyűjtőknél a `collection: true` és a `members` lista is
megjelenik.

A gyűjtés egy szintű:

- 1–64 különböző, létező **egyedi** szabály lehet tag;
- gyűjtő nem tartalmazhat másik gyűjtőt, önmagát, a fenntartott, régi
  azonosítót vagy teljes hozzáférésű szabályt;
- a tagokat a kiértékeléskor oldjuk fel; körkörös vagy hiányzó hivatkozás
  esetén a gyűjtő nem ad hozzáférést (fail closed), a hibás bejegyzést a
  betöltés naplózza és kihagyja.

## Domain szabály

A domain szabály (`domains` lista) a Caddy-alapú aldomain-proxy
bejegyzéseit (Admin → **Domainek**) nyitja meg, nevük szerint. Nincs
iránya, portja, ICMP-je és teljes hozzáférése, és soha nem nyúl az
nftables-hez: a `grants` listája üres, ezért kiadáskor és visszavonáskor
sincs kernel-elem. Csak létező proxy-bejegyzésre hivatkozhat (mentéskor
ellenőrizve); amíg hivatkozik, a bejegyzés nem törölhető és nem nevezhető
át. Gyűjtő tagja lehet: a feloldott gyűjtő `domains` mezője a tagok
domainjeinek uniója. Csak kifejezett kiosztással választható (a kiosztás
nélküli régi fiók nem örökli), és a teljes hozzáférés vagy az admin
szerepkör sem helyettesíti.

```json
{
  "label": "OWUI",
  "description": "",
  "domains": ["owui"],
  "default_ttl": 3600,
  "max_ttl": 86400,
  "created": 1792500000
}
```

A payload ugyanez `action`/`id` mellett; `tcp`, `udp`, `icmp` és `full` nem
adható meg értékkel. A felületen a `ports_label` a teljes hostneveket
mutatja (`Domain: owui.z1.example.com`).

## Tárolás (`rules.json`)

Az egyedi szabályok tárolása: `label`, `description`, `tcp`, `udp`, `icmp`,
`full`, `direction`, `default_ttl`, `max_ttl`, `created`. A `direction`
hiányzó értéke betöltéskor `forward`.

A gyűjtőszabály bejegyzése csak ezeket tartalmazza:

```json
{
  "label": "Web + DNS",
  "description": "Két egyedi szabály együtt",
  "members": ["web-only", "dns-only"],
  "default_ttl": 300,
  "max_ttl": 3600,
  "created": 1792500000
}
```

A `tcp`, `udp`, `icmp`, `full` és `direction` mezők szándékosan hiányoznak:
a portok és az irány számított értékek, és nem perzisztálódnak. Így egy tag
későbbi módosítása nem hagy maga után elavult uniót vagy irányt. A betöltés a
`members` mező meglétéből ismeri fel a gyűjtőt, ellenőrzi a hivatkozásokat, és
a hibás gyűjtőket a többi hibás szabályhoz hasonlóan naplózza és kihagyja.
Egy régebbi fájlban maradt `direction` mezőt a betöltés figyelmen kívül hagy.

## API

Az admin végpont továbbra is a `POST /api/admin/rules`. A válasz a teljes
admin állapot (`_admin_state()`), sikeres duplikálásnál ezen felül
`"message": "Szabály duplikálva."`.

### Egyedi szabály létrehozása vagy módosítása

```json
{
  "action": "create",
  "id": "web-only",
  "label": "Csak web",
  "description": "",
  "collection": false,
  "direction": "forward",
  "tcp": [80, 443],
  "udp": [443],
  "icmp": false,
  "full": false,
  "default_ttl": 300,
  "max_ttl": 3600
}
```

### Gyűjtőszabály létrehozása vagy módosítása

```json
{
  "action": "create",
  "id": "web-dns",
  "label": "Web + DNS",
  "description": "",
  "collection": true,
  "members": ["web-only", "dns-only"],
  "default_ttl": 300,
  "max_ttl": 3600
}
```

A gyűjtőszabály payloadja nem tartalmaz `direction` mezőt (ha mégis
megérkezik, a rendszer figyelmen kívül hagyja; a tagok irányai döntenek). A
gyűjtő mód akkor is bekapcsol, ha a `collection` mező hiányzik, de a
`members` lista nem üres. Gyűjtőnél a `tcp`, `udp`, `icmp` és `full` mezők
nem adhatók meg értékkel. Egyedi szabálynál a `collection: false` mellett a
megszokott portmezők és a `direction` érvényesek; a `members` mezőt
figyelmen kívül hagyja a rendszer, ha üres.

Szerkesztéskor a szabály egyedi és gyűjtő mód között átváltható, a
`created` időbélyeg megmarad. Ha egy egyedi szabály tagja valamelyik
gyűjtőnek, előbb ki kell venni a gyűjtőkből, mielőtt maga is gyűjtővé vagy
teljes hozzáférésűvé alakítható lenne; így nem jöhet létre két szintű
gyűjtés, és a gyűjtő uniója sem válik érvénytelenné.

### Duplikálás

```json
{
  "action": "duplicate",
  "id": "web-only",
  "label": "Csak web — másolat",
  "new_id": "web-only-copy"
}
```

- Az `id` kötelező, a `label` és a `new_id` opcionális.
- Új azonosító nélkül a rendszer a forrás azonosítójából képez egyedit:
  `web-only-copy`, majd ütközés esetén `web-only-2`, `web-only-3`, … A
  generált azonosító legfeljebb 32 karakter, és megfelel a szabály-azonosító
  formátumnak.
- Alapértelmezett név: `<forrás név> (copy)`; a felület lokalizált
  „másolat” utótagot küld.
- A másolat átveszi a leírást, a TTL-eket, valamint egyedi szabály esetén a
  portokat/ICMP-t/teljes hozzáférést, gyűjtő esetén a taglistát. Gyűjtőnél
  a feloldott portok **nem** íródnak a másolat tárolt mezőibe.
- A fenntartott, régi azonosító nem duplikálható; a művelet nem nyúl az nftables-hez, és
  önmagában nem ad hozzáférést senkinek.

### Hibák

A hibák HTTP 400-zal, magyar `error` szöveggel érkeznek, például:

- `members: 1–64 szabály-azonosítóból álló lista kell`
- `members: legalább 1 és legfeljebb 64 egyedi szabály kell`
- `members: ismétlődő szabály-azonosító`
- `ismeretlen szabály a gyűjtőszabályban: …`
- `a gyűjtőszabály nem tartalmazhat másik gyűjtőszabályt: …`
- `a gyűjtőszabály nem tartalmazhat teljes hozzáférésű szabályt: …`
- `a(z) … szabály nem törölhető, mert tagja a következő gyűjtőszabályoknak: …; előbb vedd ki a tagok közül`

## Munkamenetek visszavonása

Ha egy egyedi szabályt módosítanak, és az tagja egy vagy több gyűjtőnek,
a rendszer a szabály saját választásai mellett az érintett gyűjtők
választásait is visszavonja, mert a gyűjtő portuniója megváltozhatott. A
több egyidejű hozzáférést használó munkamenetből csak a módosított
szabályhoz és a függő gyűjtőkhöz tartozó választás tűnik el; a többi
választás az eredeti lejárattal megmarad. Ha nem marad választás, a
munkamenet megszűnik. Az admin napló `admin_rule_updated` eseménye
tartalmazza a `collections_affected` listát és a `sessions_revoked` számot.
A gyűjtő saját módosítása vagy törlése a gyűjtő választását vonja vissza.

A portál a következő státuszfrissítéskor áthozza a friss szabálylistát. A
visszavont választás eltűnik a kijelölésből, a felület jelzi, hogy az
érintett hozzáférést újra kell engedélyezni, és a módosított definíció
csak ezzel az új, kifejezett engedélyezéssel kerül a tűzfalba. A már futó
kapcsolat a visszavonás pillanatában megszakadhat.

## Törlés

- Egy gyűjtő törlése csak a gyűjtőt törli; a tagok érintetlenek maradnak.
- Egy tag nem törölhető, amíg bármely gyűjtő tartalmazza. A hiba felsorolja
  a gyűjtők azonosítóit; előbb a gyűjtőkből kell eltávolítani a tagot.

## Korlátok

- Csak egy szintű gyűjtés; beágyazott gyűjtő nem hozható létre.
- A gyűjtő portjai uniók, nem metszetek; a tagok külön-külön is választhatók
  maradnak, ha hozzájuk vannak rendelve.
- Gyűjtő nem adhat teljes hozzáférést, és teljes hozzáférésű szabály nem
  lehet tag.
- A gyűjtőnek nincs saját iránya, és a felület a gyűjtő módban nem kínál
  irányválasztót. A tagok lehetnek forward és host (`input`) irányúak is;
  minden tag a saját irányában kap engedélyt, a host szabályok portkorlátai
  (nincs teljes hozzáférés/ICMP, csak a 8100 fenntartott) pedig a host
  tagokra érvényesek. A gyűjtő a 22-es portot csak egy olyan input irányú
  tagon keresztül nyithatja meg, amely kifejezetten felsorolja a 22-t. A
  teljes hozzáférésű tag továbbra is elutasított; a 3.0.0 előtti kiadások
  teljes hozzáférésű azonosítója fenntartott, nem hozható létre és nem
  lehet tag. Részletek: [host-rules.md](host-rules.md).
- A host SSH-t kizárólag egy admin által létrehozott, a 22-es TCP-portot
  kifejezetten tartalmazó host szabály nyitja meg (közvetlenül vagy
  gyűjtőtagon keresztül), aktív, engedélyezett portál-munkamenettel. Egyedi
  teljes hozzáférésű szabály és teljes hozzáférésű gyűjtőtag nem.
- A duplikálás nem rendeli hozzá automatikusan az új szabályt felhasználóhoz
  vagy csoporthoz.
- A gyűjtő és a duplikált szabály létrehozása nem módosítja közvetlenül a
  tűzfalat; hozzáférést csak a szokásos belépési/engedélyezési folyamat ad.
