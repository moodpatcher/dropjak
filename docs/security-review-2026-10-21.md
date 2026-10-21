# Dropjak / határvédelem — biztonsági jelentés

**Dátum:** 2026-10-21
**Módszer:** statikus kódátnézés (`server.py`, `gateway.py`, `fail2ban.py`,
`settings_store.py`, `deploy/hatarvedelem.nft`, `docker/entrypoint.sh`,
`index.html`). Élő VM-et nem érintett, tesztet nem futtatott.
**Állapot:** csak jelentés; semmilyen kódot nem módosított.

## Összkép

A rendszer jól meg van erősítve. A klasszikus betörési utak le vannak zárva:
nincs shell-injekció, nincs nft-injekció, nincs path traversal, nincs XSS, és
az auth-réteg időzítés- és visszajátszás-védett. A talált pontok nem
kódhibák, hanem telepítési és maradék-kockázatok — de ezek közül az első a
jelenlegi élő konfigurációban valós és súlyos.

## Találatok rangsorolva

### 1. MAGAS — Titkosítatlan HTTP a nyílt internet felé

A fő kockázat nem a kódban van, hanem a futtatás módjában. Az élő konfiguráció
`HV_PORTAL_NET=0.0.0.0/0` (portál az egész internetnek), a `HV_COOKIE_SECURE`
alapértéke `0`, és nincs TLS (`gateway.py:265`). Így a **jelszó, a TOTP-kód, a
recovery code és a munkamenet-süti mind tisztán, titkosítatlanul utazik** a
WAN-on. Bárki az útvonalon (upstream szolgáltató, adatközpont, azonos
szegmens) elkaphatja a hitelesítő adatokat.

- Enyhítő tény: a munkamenet IP-hez kötött (`gateway.py:6353`), ezért egy
  ellopott süti más IP-ről nem használható. De aki a *jelszót + TOTP-kódot*
  kapja el, vagy ugyanazon az IP-n / NAT mögött ül, teljesen belép.
- A `docs/caddy-proxy-terv.md` ezt már ismeri (elhalasztva). Riportszinten ez
  a legfontosabb tétel.
- **Interim enyhítés:** szűkítsd a `HV_PORTAL_NET`-et egy menedzsment-CIDR-re,
  vagy tegyél elé TLS-terminálást, mielőtt WAN-ról elérhető marad.

### 2. KÖZEPES — A MAC-anti-spoofing csak a LAN-forrásokat védi

A `binds_mac()` csak a `HV_LAN_NET`-en belüli IP-re ad `True`-t
(`gateway.py:3045-3052`). **Minden LAN-on kívüli forrás** (azaz a 0.0.0.0/0
miatt az összes WAN-kliens) MAC-kötés **nélkül** kap grantet, és a forward
port-accept, valamint az input host-accept szabályoknak nincs `iifname`
megkötése (`deploy/hatarvedelem.nft:245-250, 444-445`). Tehát az „5.1.4
MAC-kötés a LAN-on" invariáns a gyakorlatban csak LAN-forrásra igaz. A LAN-on
belül pedig egy aktív támadó az IP-t és a MAC-et is klónozhatja ugyanarról az
L2-szegmensről.

**Következmény:** a MAC-kötést ne tekintsd hozzáférési határnak — csak passzív
IP-újrahasznosítás (DHCP-csere) ellen emel korlátot. A dokumentáció elismeri,
hogy „MAC ≠ hitelesítés"; ez a pont konkretizálja, mennyire szűk a védelem.

### 3. KÖZEPES / ALACSONY — IP-alapú identitás + carrier-NAT ütközés

A munkamenet IP-nként egy, a fail2ban pedig forrás-IP szerint tilt. A
0.0.0.0/0 kitettség mellett a carrier-NAT mögötti kliensek (sok felhasználó →
egy publikus IP) esetén:

- az egyik felhasználó belépése kidobja a másikét;
- **egyetlen rosszindulatú felhasználó kitiltathatja az egész NAT mögötti
  kört** (DoS), sőt az `on_ban` más felhasználók munkamenetét is bontja.

IP-alapú kapuzás velejárója. Ha a WAN-kitettség marad, érdemes rövidebb
ban-idő és magasabb küszöb.

### 4. ALACSONY — Nincs globális plafon a függő regisztrációkra

`registration_enabled=true` esetén forrás-IP-nként 3/10 perc a limit
(`server.py:1579`), de a **függő fiókok teljes számára nincs korlát**. Idővel
vagy sok IP-ről a `users.json` korlátlanul nő; minden indításkor betöltődik és
validálódik, lassítva a startot és az admin Users fület. Javaslat:
max-pending plafon és/vagy a jóvá nem hagyott kérelmek lejáratása.

## Amit ellenőrzött és rendben van (nem találat)

- **nft-hívások:** argv-lista, nincs `shell=True` (`gateway.py:2724`); az
  `nft -f -` scriptbe csak `int`-re validált portok és `ipaddress`-szel
  kanonizált célcímek kerülnek (`_custom_dst`, `_custom_ports`) —
  újsor-/szintaxis-injekció nem lehetséges.
- **entrypoint:** minden helyőrző-env validált a renderelés előtt (ifname
  charset, CIDR Pythonnal, numerikus port/group, hex mark) —
  `docker/entrypoint.sh:134-144`.
- **Jelszó:** PBKDF2-HMAC-SHA256 600k iteráció + dummy-digest időzítés-védelem
  (`gateway.py:4844`).
- **TOTP:** konstans idejű, visszajátszás-védett `totp_last_step`-pel, zár
  alatt (`gateway.py:5204-5236`); recovery code konstans idejű, egyszer
  használatos.
- **PoW captcha:** HMAC-aláírt (nehézség nem csökkenthető), replay-védett
  (`gateway.py:6982`). Gyenge by-design; a valódi brute-force gát a fail2ban.
- **Jogosultság:** `resolve_for` csak a felhasználóhoz rendelt szabályt enged
  (`gateway.py:2069-2081`); az admin-guard minden kérésnél a friss
  user-rekordot nézi (`server.py:600`).
- **Munkamenet:** IP-hez kötött, IP-váltáskor azonnal visszavonva
  (`gateway.py:6353`); a kliens IP a socket-peerből, nem az
  `X-Forwarded-For`-ból (`server.py:435`).
- **nft logika:** a forward láncban nincs általános `established accept`
  megkerülő; a visszavonás a `ct original` egyezésen át azonnal vág; az input
  lánc őr-szabályai (SSH/22, DNS/53, host_service_*) konzisztensen lezárják az
  elárvult folyamokat.
- **UI:** minden felhasználói adat `textContent`-tel renderelődik; az egyetlen
  dinamikus `innerHTML` út csak belső ikon-SVG-t kap — nincs tárolt XSS. Az
  admin-state nem szivárogtat titkot (hash/secret/recovery kimarad,
  `gateway.py:4690-4700`).

## Amit nem néztem

- Nem futtatta az 563 tesztet, és nem tesztelt élő VM-en (a projektszabály
  tiltja a tűzfal betöltését fejlesztőgépen) — az nft-megállapítások a sablon
  statikus olvasatából jönnek, nem kernel-méréssel igazoltak.
- A `droplog.py` netlink-parsert és a `fail2ban.py` belső számlálóit csak
  felületesen nézte.

## Záró kockázatértékelés

A #1 (titkosítatlan HTTP WAN-on) a jelenlegi élő konfigurációban valós, nem
elméleti — ez a legfontosabb teendő. A #2–#3 a 0.0.0.0/0 kitettséggel
súlyosbodik; a `HV_PORTAL_NET` szűkítése egyszerre enyhíti mindhármat.
