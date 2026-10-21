# Host (input) szabályok

A Dropjak szabályai alapértelmezés szerint **forward** irányúak: a kapu a
kliens forgalmát továbbítja az internet vagy egy Docker által publikált
konténer felé. A portálgép **saját** szolgáltatásait (például egy
`mpwerks` játékszervert a 25566-os porton) a forward szabályok nem teszik
elérhetővé, mert azok nem a host felé menő, hanem a rajta átmenő forgalmat
nyitják. Erre való a **host** (`input`) irány.

## Létrehozás

1. **Admin → Szabályok → Új szabály**.
2. Az **Irány** mezőben válaszd az **Input (host)** értéket.
3. Add meg a szükséges TCP- és/vagy UDP-portokat, például TCP 25566.
4. Állítsd be az alapértelmezett és maximális időtartamot, majd mentés.
5. Rendeld a szabályt a felhasználóhoz vagy csoporthoz, és a belépőoldalon
   a kliens válassza ki a hozzáféréshez.

Példa a `mpwerks` szerverhez:

```
Azonosító:   mpwerks-host
Név:         mpwerks (host)
Irány:       Input (host)
TCP portok:  25566
UDP portok:  25566   (ha a szolgáltatás UDP-t is használ)
```

A host szabály ugyanúgy választható a belépőoldalon, mint bármely más
szabály; a listában a **Host** jelzés különbözteti meg.

## Működés

- A portál a belépett kliens **IP-címét** teszi be a
  `allowed_input_tcp` / `allowed_input_udp` nftables halmazba, a
  munkamenet TTL-jével. Más kliens nem éri el a szolgáltatást.
- LAN-on a szokásos **MAC-kötés** is érvényes: a forrás-IP önmagában nem
  elegendő. WAN felől a szabály a kliens IP-jére nyílik, MAC-kötés nélkül.
- A **fail2ban** tiltás és a MAC-hamisítás elleni drop-szabályok a host
  elfogadó szabály **előtt** futnak, tehát egy tiltott kliens a host
  szabállyal sem érheti el a szolgáltatást.
- Kilépéskor, lejáratkor vagy adminisztrátori visszavonáskor a portál törli
  a halmazelemeket. A meglévő kapcsolatokat nem csak a conntrack flush zárja
  le: a portál a szabályokban valaha szerepelt minden host portot felvesz a
  `host_service_tcp` / `host_service_udp` kerneloldali halmazba (csak
  hozzáad, futás közben soha nem töröl). Az input lánc az established,
  kliens→host csomagok célportját veti össze ezekkel, és eldobja a forgalmat,
  ha a forrás IP már nincs az `allowed_input_tcp` / `allowed_input_udp`
  halmazban. A host DNS (53) és a DHCP meglévő elfogadó szabályai az őr előtt
  futnak, ezért a forward DNS és a címújítás nem törik el. Így a kapcsolat
  akkor is megszakad, ha a conntrack flush elmarad (összeomlás, hiányzó
  conntrack), vagy a kernel (`nf_conntrack_tcp_loose`) a következő ACK-ból
  újra létrehozza a folyamot. Ha a portál összeomlik, a kerneloldali timeout
  továbbra is lejár.
- A host szabály LAN-ról és WAN-ról egyaránt működik: az elfogadó szabálynak
  nincs `iifname` feltétele, ezért WAN felől is érvényes, ha a forrás IP-je
  engedélyezett portál-munkamenethez tartozik. A portál a TCP 80 esetleges
  host-engedélyét kiveszi a portál-átirányítás alól.

## SSH a hostra

Az első indulás admin fiók nélkül megszakítja az aktuális SSH-munkamenetet;
ha a `breakglass` lánc nem elérhető, a szolgáltatói konzol a helyreállítás
útja.

A host SSH-nak egyetlen útvonala van: egy admin által létrehozott host
szabály az `allowed_input_tcp` halmazban deklarált `(IP, 22)` párral nyitja
meg a TCP 22-es portot. Aktív, engedélyezett portál-munkamenet kell
ugyanarról az IP-címről, és a meglévő SSH-folyamat is csak addig marad
életben, amíg ez az útvonal érvényes. Az UDP 22 közönséges host-port, nem
SSH. A `services.json` `admin` nevű bejáratott szolgáltatása kimenő
(kliensoldali) SSH-t jelent forward irányban; az nem a portálgép host SSH-ja.

Az első szabálykészlet betöltése megszakíthatja az éppen futó SSH-
kapcsolatot, ha még nincs a belépő adminhoz rendelt, TCP 22-t engedélyező
host szabály. Első indulás előtt hozd létre az admin fiókot, rendeld hozzá
a host SSH szabályt, és tartsd nyitva a szolgáltatói (out-of-band) konzolt.
Ha erre nincs mód, a `HV_SKIP_FIREWALL=1` értékkel indítható a konténer,
majd a szabály és a hozzárendelés elkészítése után újraindítható
tűzfalbetöltéssel.

Minden konténer-restart üríti a dinamikus halmazokat, ezért a host SSH is
bezárul: a kliensnek újra be kell jelentkeznie és engedélyeznie kell a host
szabályt. A kerneloldali timeout lejárta, a kilépés és az adminisztrátori
visszavonás szintén azonnal törli az `(IP, 22)` elemet.

## Korlátok

- Csak **explicit TCP/UDP port** adható meg. Teljes hozzáférés, ICMP és a
  régi szolgáltatáslista nem használható host szabályban.
- Csak a **8100-as port (portál)** fenntartott: sem a portál validációja, sem
  a kernel host-elfogadása nem engedi megnyitni. A **TCP 22-es port (SSH)**
  adminisztrátor által létrehozott host szabállyal megnyitható; az UDP 22
  közönséges host-port, nem SSH. Egyedi teljes hozzáférésű szabály továbbra
  sem nyit SSH-t. Az SSH-útvonal aktív, engedélyezett portál-munkamenetet
  igényel ugyanarról az IP-címről.
- A szolgáltatásnak a portálgép **0.0.0.0**-n (vagy a külső interfészen)
  kell figyelnie, nem csak `127.0.0.1`-en. Ellenőrizd a host saját
  tűzfalát is: a Dropjak csak az `inet hatarvedelem` táblát kezeli.
- A gyűjtőszabályokra is érvényes: a tagok lehetnek forward és host
  (`input`) irányúak is; minden tag a saját irányában kap engedélyt. Egy
  vegyes gyűjtő host része az `allowed_input_*` halmazokba kerül, és ugyanúgy
  a `host_service_*` őrhalmaz védi, mint az önálló host szabályt. A host
  tagokra a fenti portkorlátok (nincs teljes hozzáférés/ICMP, csak a 8100
  fenntartott) érvényesek. A gyűjtő a TCP 22-es portot csak egy olyan input
  irányú tagon keresztül nyithatja meg, amely kifejezetten felsorolja a TCP
  22-t; teljes hozzáférésű tag továbbra sem lehet.

## Gyors próba

A portálgépen indíts egy ideiglenes figyelőt:

```bash
nc -l 25566
```

(Egyes `netcat` változatoknál `nc -l -p 25566` a helyes alak.) Ezután egy
engedélyezett kliensről:

```bash
nc <portálgép-ip-címe> 25566
```

Ha a kapcsolat létrejön, a host szabály működik. Ha nem, ellenőrizd, hogy a
kliens munkamenete aktív-e, a szolgáltatás a megfelelő interfészen figyel-e,
és hogy a host saját tűzfala nem dobja-e el a csomagot.

## Telepítés

A host szabályokhoz a `deploy/hatarvedelem.nft` új halmazai és szabályai
kellenek. A sablon frissítése után a konténert újra kell építeni/indítani;
a dinamikus halmazok ürülnek, ezért minden kliensnek újra be kell lépnie.
Éles telepítés előtt gondoskodj egy független adminisztrátori hozzáférésről
(konzol), és ne távolítsd el a meglévő SSH-hozzáférést biztosító host
szabályt.
