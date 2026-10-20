# Gyűjtőszabályok és szabályduplikálás

A Dropjak admin felületén a szabályok mellett két kiegészítő művelet érhető
el:

- **Duplikálás** – bármely nem beépített szabály (egyedi vagy gyűjtő)
  másolása egy kattintással.
- **Gyűjtőszabály** – több meglévő egyedi szabály összevonása egyetlen
  választható hozzáférési szabállyá.

A gyűjtőszabály ugyanúgy rendelhető felhasználóhoz vagy csoporthoz, mint
bármely más szabály, és a belépőoldalon egyetlen hozzáférési lehetőségként
jelenik meg.

## Szemantika

A gyűjtőszabály nem tárol saját portokat. A TCP-, UDP- és ICMP-jogosultsága
a tagjai jogosultságainak **uniója**:

- TCP-portok: a tagok TCP-portjainak egyesítése.
- UDP-portok: a tagok UDP-portjainak egyesítése.
- ICMP: engedélyezett, ha bármelyik tag engedélyezi.
- Teljes hozzáférés: a gyűjtő soha nem adhat teljes hozzáférést, és teljes
  hozzáférésű szabály nem lehet a tagja.

A gyűjtő saját `default_ttl` és `max_ttl` értékkel rendelkezik; a belépéskor
választott időtartam ezekhez igazodik, nem a tagok TTL-jeihez. A feloldott
portlista a felület minden helyén a megszokott `ports_label` mezőben
jelenik meg, a gyűjtőknél a `collection: true` és a `members` lista is
megjelenik.

A gyűjtés egy szintű:

- 2–64 különböző, létező **egyedi** szabály lehet tag;
- gyűjtő nem tartalmazhat másik gyűjtőt, önmagát, a beépített admin
  szabályt vagy teljes hozzáférésű szabályt;
- a tagokat a kiértékeléskor oldjuk fel; körkörös vagy hiányzó hivatkozás
  esetén a gyűjtő nem ad hozzáférést (fail closed), a hibás bejegyzést a
  betöltés naplózza és kihagyja.

## Tárolás (`rules.json`)

Az egyedi szabályok tárolása változatlan: `label`, `description`, `tcp`,
`udp`, `icmp`, `full`, `default_ttl`, `max_ttl`, `created`.

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

A `tcp`, `udp`, `icmp` és `full` mezők szándékosan hiányoznak: a portok
számított értékek, és nem perzisztálódnak. Így egy tag későbbi módosítása
nem hagy maga után elavult uniót. A betöltés a `members` mező meglétéből
ismeri fel a gyűjtőt, ellenőrzi a hivatkozásokat, és a hibás gyűjtőket a
többi hibás szabályhoz hasonlóan naplózza és kihagyja.

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

A gyűjtő mód akkor is bekapcsol, ha a `collection` mező hiányzik, de a
`members` lista nem üres. Gyűjtőnél a `tcp`, `udp`, `icmp` és `full` mezők
nem adhatók meg értékkel. Egyedi szabálynál a `collection: false` mellett a
megszokott portmezők érvényesek; a `members` mezőt figyelmen kívül hagyja a
rendszer, ha üres.

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
- Beépített szabály nem duplikálható; a művelet nem nyúl az nftables-hez, és
  önmagában nem ad hozzáférést senkinek.

### Hibák

A hibák HTTP 400-zal, magyar `error` szöveggel érkeznek, például:

- `members: legalább 2 és legfeljebb 64 egyedi szabály kell`
- `members: ismétlődő szabály-azonosító`
- `ismeretlen szabály a gyűjtőszabályban: …`
- `a gyűjtőszabály nem tartalmazhat másik gyűjtőszabályt: …`
- `a gyűjtőszabály nem tartalmazhat teljes hozzáférésű szabályt: …`
- `a(z) … szabály nem törölhető, mert tagja a következő gyűjtőszabályoknak: …; előbb vedd ki a tagok közül`

## Munkamenetek visszavonása

Ha egy egyedi szabályt módosítanak, és az tagja egy vagy több gyűjtőnek, a
rendszer a szabály saját munkamenetei mellett az érintett gyűjtőkkel
engedélyezett munkameneteket is visszavonja. Ennek oka, hogy a gyűjtő
portuniója megváltozhatott. Az admin napló `admin_rule_updated` eseménye
tartalmazza a `collections_affected` listát és a `sessions_revoked` számot.
A gyűjtő saját módosítása vagy törlése a gyűjtővel engedélyezett
munkameneteket vonja vissza.

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
- A host SSH-t csak a beépített `admin-full` szabály engedélyezése nyitja
  meg; gyűjtőszabály vagy egyedi teljes hozzáférésű szabály nem.
- A duplikálás nem rendeli hozzá automatikusan az új szabályt felhasználóhoz
  vagy csoporthoz.
- A gyűjtő és a duplikált szabály létrehozása nem módosítja közvetlenül a
  tűzfalat; hozzáférést csak a szokásos belépési/engedélyezési folyamat ad.
