# Propagációs mátrix

Ez a dokumentum azt írja le, hogyan érvényesül minden adminisztratív változás
a már bejelentkezett felhasználókra, a kernel tűzfalára, a conntrackre és a
portál munkamenet-tárára: melyik kód végzi a visszavonást, mely nft elemek
tűnnek el, kell-e conntrack-ürítés, és a felhasználónak mikor kell újra
engedélyeznie magát.

A hivatkozott sorszámok a 2026-10-21-i munkafa állapotára vonatkoznak. Az
F1–F9 és F11 audit-megállapítások, valamint az N1–N3 és N5 eltérések
javítva; az F10 termékdöntéssel elfogadott (a 8100-as port literálisan
fenntartott, nem hiba), az N4-nek pedig csak a `shutdown()` útvonalán maradt
elérhetőségi maradéka. A több egyidejű hozzáférés (8. szakasz)
implementált. Jelölések: `PASS`; `PASS WITH CAVEAT (<megállapítás>)`;
`GAP (<megállapítás>)`.

## 1. Invariánsok

1. **Fail-closed forward.** A `forward` lánc `policy drop`; csak a dinamikus
   halmazokra illeszkedő, `meta mark`-kal megjelölt csomag mehet át
   (`deploy/hatarvedelem.nft:172`, `:245-250`); a Docker `DOCKER-USER` lánca
   különben eldob (`docker/entrypoint.sh:180-239`).
2. **A jelszó önmagában soha nem ad hozzáférést.** A sikeres belépés csak
   `authorized=False` munkamenetet hoz létre (`gateway.py:6211-6285`); a
   kernelbe engedélyt kizárólag a `/api/access` által hívott
   `SessionManager.authorize()` `grant_all()` hívása tesz
   (`gateway.py:6351`, `:6542`; `server.py:2470`).
3. **Az engedély az authorize pillanatában keletkezik, és minden
   jelentésváltoztató módosítás commit pontján törlődik.** A szabálytár a
   függő gyűjtőket a módosítással egy záron belül, a commit pontján adja
   vissza (`RuleStore.update_with_dependents()`, `gateway.py:2211-2227`); a
   szerver ezután azonnal visszavonja az érintett választásokat
   (`server.py:3356`). A commit és a visszavonás nem atomi, ezért
   összeomlás esetén a TTL a biztonsági háló; a visszavonás hibája nem vész
   el, hanem a korlátozott újrapróbálkozó sorba kerül (F1).
4. **A visszavonás a munkamenet-állapot zárolásával összehangolt.** Minden
   eltávolítási út a `SessionManager._lock` alatt hívja a tűzfalat:
   `logout()` (`gateway.py:6592-6612`), `terminate()` (`:6613-6630`),
   `revoke_user()` (`:6631-6663`), `revoke_user_rules()` (`:6664-6682`),
   `revoke_rule()` (`:6683-6703`), `revoke_rules()` (`:6704-6727`),
   `revoke_ip()` (`:6728-6766`), `reap_once()` (`:6767-6812`),
   `validate()` (`:6286-6350`) és a `_retry_pending_revocations()`
   (`:6059-6207`). Részleges visszavonáskor a `_subtract_grants()` kivonja a
   maradó, aktív munkamenetek által igényelt elemeket, és ilyenkor
   conntrack-ot sem ürít (`:5818-5886`, `:5887-5929`). Residual: a
   `shutdown()` (`:6837-6855`) a munkamenet eltávolítása után, a zár nélkül
   hívja a tűzfalat; ez csak elérhetőségi maradék (a munkamenet már
   megszűnt, és a zár nélküli visszavonás egy közben engedélyező új
   munkamenet portjait törölheti), biztonsági rése nem.
5. **Módosított szabály, gyűjtő, csoport vagy felhasználó soha nem foltozza
   a meglévő engedélyt.** A kód nem írja át a kernelben lévő grantot: vagy
   visszavonja, vagy érintetlenül hagyja. A szabály módosításakor a saját és
   a függő gyűjtők választásai törlődnek a munkamenetekből; ha nem marad
   választás, a munkamenet megszűnik (`server.py:3356`). A csoport
   módosításakor a régi és az új tagok teljes munkamenete szűnik meg
   (`server.py:3261`). Újraengedélyezés csak akkor kell, ha a
   munkamenetnek nem maradt választása; a maradó választásokat a rendszer az
   eredeti lejárattal újrakiadja.
6. **A kernel TTL csak biztonsági háló.** Minden timeoutos halmazba kerülő
   elem explicit `timeout`-tal kerül be (`gateway.py:3106`, `:3213`,
   `:3249`, `:3272`). A munkamenet `expires` értéke és a grant TTL-je
   ugyanaz; ha a portál meghal, a kernel a TTL-nél törli az elemet. A
   portál a lejáratkor külön is töröl: a reaper a lejárt munkamenet grantjeit
   visszavonja (a `client_mac` elemet is, `revoke_all()` `:3372-3373`), a
   fail2ban pedig a lejárt tiltásokat a memóriájából is kiszűri
   (`fail2ban.py:1107-1113`, `:478-479`). A TTL nem helyettesíti a
   visszavonást: a lejáratig szóló engedély önmagában is érvényes, ezért a
   lejárat előtti visszavonás kötelező.
7. **A `host_service_tcp` és `host_service_udp` add-only őrhalmaz, nem
   grant.** Csak a valaha deklarált host portokat tartalmazzák; a
   `sync_host_ports()` soha nem töröl belőlük, és az induláskori ürítés is
   kihagyja (`deploy/hatarvedelem.nft:80-94`, `gateway.py:3399-3441`,
   `:3716`). A méretük 65536, ezért a legfeljebb 65535 érvényes port
   mind elfér, és nem veszhet el csendben őrelem. Az egyetlen törlő út a
   `prune_host_service_ports()`, amely csak olyan portot távolít el, amelyre
   egyetlen perzisztált szabály sem hivatkozik, és amelyhez nem tartozik élő
   conntrack-bejegyzés; ha az nft-listázás vagy a conntrack nem elérhető,
   semmit nem töröl (`gateway.py:3632-3715`, `:7129-7157`). A tényleges
   host-engedély az `allowed_input_tcp`/`allowed_input_udp` halmazban van,
   TTL-lel. Az őrhalmaz csak az established forgalmat vágja el, ha az
   engedély eltűnt.
8. **A tiltás és a blokk minden engedély előtt érvényesül.** A `banned_v4`
   drop a forward és az input láncban a grantok előtt fut
   (`nft:204-205`, `:326-327`). Az admin blokk ugrás feltétel nélküli a
   forward (`nft:229`) és az input (`nft:337`) láncban; a blokk a DNAT előtti
   célportot (`ct original proto-dst`) és a conntrack eredeti tuple-ját
   használja (`gateway.py:2765-2785`), ezért a válaszirányt és a WAN/Docker
   felől érkező csomagokat is fedi. A
   `block_nat`/`preauth_nat` ugrás LAN-only (`nft:465-466`), mert a NAT
   előtti szakasz csak a LAN forgalmára releváns. Az F4 javítva.
9. **Egy IP-hez egyszerre egy munkamenet tartozik.** Új belépés ugyanarról
   az IP-ről előbb visszavonja a régi engedélyeket, majd lecseréli a
   munkamenetet (`gateway.py:6211-6285`); ha a visszavonás nem sikerül, a
   régi munkamenet is eldobódik, és az új belépés sem jön létre
   (fail-closed).
10. **A munkamenet-tár memóriabeli.** A munkamenetek nem perzisztálódnak;
    leállításkor a `shutdown()` minden engedélyt visszavon
    (`gateway.py:6837-6855`, `Gateway.stop()` `:7574`). Induláskor nincs
    munkamenet-rekonsziliáció: mindenkinek újra be kell lépnie. Az
    induláskori ürítés/egyeztetés és a nem biztonságos stale opt-in
    viselkedését az 5. szakasz írja le.
11. **Több szabály egy munkamenetben.** A munkamenet a kiválasztott
    szabályokat a `rules` és `rule_parts` mezőkben tárolja
    (`gateway.py:5398-5399`); a `rule`/`rule_label` csak az első választás
    kompatibilitási nézete. A tényleges engedély a választások irányonkénti
    uniója (`union_grants()`, `gateway.py:445-497`): a `full` ugyanabban az
    irányban elnyeli a TCP/UDP/ICMP részeket, az átfedő portok egyszer
    szerepelnek, az üres irányok kimaradnak. Az admin listázás
    `selected_rules`, `selected_rule_labels` és irányonkénti `grants`
    mezőket kap (`gateway.py:5433-5460`).
12. **Egy munkamenet-TTL, a legszigorúbb szabály szerint.** Az
    `authorize()` a kiválasztott szabályok `max_ttl` értékei közül a
    legkisebbet tekinti felső korlátnak; a túl hosszú kérés `AccessError`,
    nem csonkolás (`gateway.py:6398-6413`). Egy munkamenetnek egyetlen
    `expires` értéke van.
13. **A részleges visszavonás csak a távozó választást érinti.** A
    `_remove_selections_locked()` a megadott szabály-azonosítókat törli a
    munkamenet `rule_parts` listájából; ha marad választás, az eredeti
    lejárat változatlan, a távozó unió pontos elemeit `revoke_exact` törli,
    a maradó uniót `grant_all()` újrakiadja (mert egy korábbi `full` grant
    elfedhette a portelemeket), és a conntrack csak a távozó portokra
    célzott (`gateway.py:5930-6057`). Lejárt munkamenet nem kap vissza
    semmit: teljesen eltávolítódik (`:5978-5988`). Ha nincs maradó
    választás, a munkamenet megszűnik.
14. **Fail-closed többes engedélyezésnél és részleges visszavonásnál.** A
    HTTP réteg minden kiválasztott azonosítót az `authorize()` előtt old
    fel (`server.py:2586-2592`), így egy hibás azonosító nem hagy részleges
    grantet. Bármely tűzfalhiba esetén a munkamenet eldobódik, a régi unió
    visszavonása megtörténik (szükség esetén a függő sorba állítva), és a
    HTTP 503-at ad (`gateway.py:6495-6535`; `server.py:2599-2612`). A
    részleges eltávolítás hibája ugyanígy a teljes munkamenet eldobásával és
    a régi unió visszavonásával zár (`gateway.py:6035-6056`).

## 2. Az érintett munkamenetek felderítése

- **Közvetlen találat:** `rule_id in session.rules` vagy a régi,
  egy-szabályos alaknál `session.rule == <szabály-id>`; a választás részletei
  a `session.rule_parts`-ban vannak (`Session`, `gateway.py:5371-5399`),
  csak engedélyezett munkamenetnél kitöltve (`:6567-6585`). A
  `revoke_rule()` ezt használja (`:6683-6703`), és több választás esetén
  csak a megadott szabályt törli; a `revoke_rules()` több azonosítót egy
  zárolás alatt, egy menetben távolít el (`:6704-6727`).
- **Függő gyűjtők:** a `RuleStore.update_with_dependents()` a módosítással
  egy záron belül, a commit pontján adja vissza a függő gyűjtők azonosítóit
  (`gateway.py:2211-2227`), így közben létrehozott gyűjtő sem maradhat ki.
  A szerver a szabályt és a függőket egyetlen
  `revoke_rules((rule.id, *dependents))` hívással vonja vissza
  (`server.py:3345-3357`); a munkamenetből csak az érintett választások
  tűnnek el, a többi választás grantje megmarad. Gyűjtő tagjának
  hozzáadása/eltávolítása csak a gyűjtőt választók munkameneteit érinti, a
  tag saját választásai érintetlenek maradnak.
- **Csoporthozzárendelés:** az érintett halmaz a régi és az új tagok uniója
  (`affected = set(existing.members) | set(updated.members)`,
  `server.py:3261`), törléskor a csoport tagjai (`:3274`). A csoporthoz
  rendelt szabályok a `effective_for()` nézeten át érvényesülnek
  (`gateway.py:1896`), ezért a csoport releváns módosítása a tagok teljes
  munkamenetét bontja (`revoke_user()`).
- **Felhasználó-identitás:** a munkamenet `user` mezője; a `revoke_user()`
  minden munkamenetet (opcionálisan egy kivételével) és grantjeit vonja
  vissza (`gateway.py:6631-6663`).
- **Egy-IP-egy-munkamenet és csere:** a `login()` a régi, ugyanahhoz az
  IP-hez tartozó engedélyeket a zár alatt visszavonja, majd a munkamenetet
  `session_replaced` eseménnyel lecseréli (`gateway.py:6211-6285`); a
  `revoke_ip()` a függő sorban lévő granteket is IP-hez tartozóként törli,
  és a zár alatt `discover=True` módon felderíti az árva host/forward
  elemeket is (`gateway.py:6728-6766`).

## 3. Fő mátrix

Az oszlopok minden táblában azonosak; az „Újraengedélyezés” azt jelzi, hogy
a művelet után ismét át kell-e menni a kétfázisú engedélyezésen.

### 3.1. Szabályok és gyűjtők

| Művelet | Érintett munkamenet és felderítés | nft elem/halmaz | conntrack | Portál/audit | Újraengedélyezés | Állapot |
|---|---|---|---|---|---|---|
| M1. Egyedi szabály létrehozása | Nincs: az új szabály nincs senkihez rendelve | Nincs; opcionálisan `host_service_*` sync | Nincs | `admin_rule_created`; `sync_host_ports()` (`server.py:3343`) | Nem | PASS |
| M2. Duplikálás | Nincs: a másolat nincs hozzárendelve | Nincs; `sync_host_ports()` | Nincs | `admin_rule_duplicated` | Nem | PASS |
| M3. Egyedi szabály módosítása | `session.rules`/`rule_parts` tartalmazza az id-t, valamint a függő gyűjtők munkamenetei (`update_with_dependents`, `gateway.py:2211-2227`; `revoke_rules`, `:6704-6727`). Csak az érintett választás törlődik (`_remove_selections_locked`, `:5930-6057`), a többi választás megmarad | A távozó választás pontos elemei (`revoke_exact`); a maradó unió újrakiadása `grant_all()`-lal, ha egy távozó `full` eddig elfedte | Célzott `conntrack_flush_removed()`; IP-s teljes ürítés csak akkor, ha semmi nem marad engedélyezve (`gateway.py:4052-4184`, `:6049-6055`) | `admin_rule_updated` (`collections_affected`, `sessions_revoked`); `sync_host_ports()` | Csak akkor, ha a munkamenetnek nem maradt választása | PASS |
| M4. Gyűjtő módosítása (portok/tagok/TTL) | `session.rules`/`rule_parts` tartalmazza a gyűjtő id-jét (`gateway.py:6683-6703`); csak a gyűjtő választása törlődik, a többi választás megmarad | A gyűjtő választásának pontos elemei; a maradó unió újrakiadása | Célzott; teljes IP-ürítés csak üres maradéknál | `admin_rule_updated`; `sync_host_ports()` | Csak akkor, ha nem maradt választás | PASS |
| M5. Gyűjtő tagjának hozzáadása/eltávolítása | Csak a gyűjtőt választó munkamenetek; a tag saját munkamenetei nem. A munkamenetből csak a gyűjtő választása tűnik el, más választásai megmaradnak | A gyűjtő választásának pontos elemei; a tag grantjei érintetlenek | Célzott a gyűjtő távozó portjaira | `admin_rule_updated`, `collections_affected` | Csak akkor, ha nem maradt választás | PASS |
| M6. Egyedi szabály törlése | Csak nem gyűjtőtag; gyűjtőtag törlése `RuleStoreError` (`gateway.py:2309-2330`). `session.rules`/`rule_parts` tartalmazza az id-t; a felhasználó/csoport hozzárendelések törlődnek. Csak az érintett választás törlődik (`revoke_rule`, `:6683-6703`) | A szabály választásának pontos elemei; `host_service_*` szándékosan megmarad | Célzott; teljes IP-ürítés csak üres maradéknál | `admin_rule_deleted` (`users_changed`, `groups_changed`, `sessions_revoked`) | Csak akkor, ha nem maradt választás | PASS |
| M7. Gyűjtő törlése | `session.rules`/`rule_parts` tartalmazza a gyűjtő id-jét; a tagok választásai érintetlenek. Csak a gyűjtő választása törlődik | A gyűjtő választásának pontos elemei | Célzott; teljes IP-ürítés csak üres maradéknál | `admin_rule_deleted` | Csak akkor, ha nem maradt választás | PASS |

### 3.2. Csoportok

| Művelet | Érintett munkamenet és felderítés | nft elem/halmaz | conntrack | Portál/audit | Újraengedélyezés | Állapot |
|---|---|---|---|---|---|---|
| M8. Csoport létrehozása | Nincs | Nincs | Nincs | `admin_group_created` | Nem | PASS |
| M9. Csoport módosítása (szabályok, tagok, név) | Régi ∪ új tagok összes munkamenete (`server.py:3167-3169`) | A tagok grantjei, irányonként | Igen, tag-IP-nként | `admin_group_updated` (`sessions_revoked`) | Igen | PASS |
| M10. Csoport törlése | A törölt csoport tagjai (`server.py:3184`) | A tagok grantjei | Igen | `admin_group_deleted` | Igen | PASS |

A csoporthoz rendelt szabályok módosítása nem külön művelet: a csoport
`rules` listájának írása az M9 sor, és ugyanazt a visszavonást végzi.

### 3.3. Felhasználók

| Művelet | Érintett munkamenet és felderítés | nft elem/halmaz | conntrack | Portál/audit | Újraengedélyezés | Állapot |
|---|---|---|---|---|---|---|
| M11. Felhasználó létrehozása | Nincs; új fiók | Nincs | Nincs | `admin_user_created` | Nem | PASS |
| M12. Jóváhagyás | Nincs: a pending fiók be sem tud lépni (`server.py:1721-1734`) | Nincs | Nincs | `registration_approved` | Nem, a következő belépésig | PASS |
| M13. Elutasítás | Pending fiók: nincs élő munkamenet; a maradék csoporttagság és jegyek törlődnek (`server.py:2894-2896`) | Nincs | Nincs | `registration_rejected` (`sessions_revoked`, `tickets_revoked`) | Nem | PASS |
| M14. Admin felhasználó-módosítás (szerep, enabled, szabályok, csoportok, jelszó, metadata, must_change, totp_required) | `revoke_user(name)`: minden munkamenet, a módosítások előtt (`server.py:2958-2962`); hiba esetén a jelszó visszaáll (`:2984-2991`) | A felhasználó összes grantje | Igen | `admin_user_updated` (`sessions_revoked`, `tickets_revoked` letiltáskor) | Igen | PASS |
| M15. Saját jelszócsere | Minden más munkamenet; a jelenlegi kivételével (`server.py:2717-2719`) | A többi munkamenet grantjei | Igen | `password_changed` | A többi eszközön igen | PASS |
| M16. Felhasználó törlése (HTTP) | `revoke_user(name)`; csoporttagság és 2FA-jegyek törlése (`server.py:3080-3083`) | A felhasználó grantjei | Igen | `admin_user_deleted` | Nem, a fiók megszűnt | PASS |
| M17. 2FA reset (HTTP) | `reset_totp()` után `revoke_user()` és jegyek (`server.py:3048-3049`) | A felhasználó grantjei | Igen | `admin_totp_reset` | Igen | PASS |
| M18. CLI `user add` / `passwd` | A démonon a vezérlőcsatornán át (`server.py:4580-4589`, `:4607-4614`); helyi írás csak akkor, ha nincs élő démon (`_control_mutation`, `:4420-4468`). A démon a meglévő azonos nevű munkameneteket is bontja (`:3700-3701`, `:3725-3730`) | Démon-úton a grantek visszavonása; helyi módban nincs daemon és nincs élő munkamenet | Démon-úton igen; helyi módban nincs élő munkamenet | `cli_user_created` / `cli_password_changed` | Démon-úton igen; helyi módban nincs élő munkamenet | PASS |
| M19. CLI `user del` | Démonon (`server.py:3744-3776`), a csoporttagság törlésével (`:3762`) és visszavonással (`:3763-3764`); helyi módban a csoporttisztítás szintén megtörténik (`:4633-4636`) | Démon-úton a grantek; helyi módban nincs élő munkamenet | Démon-úton igen; helyi módban nincs | `cli_user_deleted` | Démon-úton igen; helyi módban nincs | PASS |
| M20. CLI `user totp-reset` | Démonon (`server.py:3778-3810`, visszavonás `:3796-3797`); helyi mód csak élő démon nélkül | Démon-úton a grantek; helyi módban nincs élő munkamenet | Démon-úton igen; helyi módban nincs | `cli_totp_reset` | Démon-úton igen; helyi módban nincs | PASS |

### 3.4. Fail2ban

| Művelet | Érintett munkamenet és felderítés | nft elem/halmaz | conntrack | Portál/audit | Újraengedélyezés | Állapot |
|---|---|---|---|---|---|---|
| M21. Kézi tiltás (HTTP) | `_on_fail2ban_ban` → `sessions.revoke_ip(ip)` (`gateway.py:6727-6728`) | `banned_v4` elem explicit timeouttal; a granteket a tiltás előtt a kernel amúgy is eldobja | Igen | `fail2ban_ban`; drop-log esemény | Igen, a tiltás lejárta után | PASS |
| M22. Kézi feloldás / összes feloldása (HTTP) | Nincs visszavonás; a tiltás megszűnése nem ad vissza régi grantet | `banned_v4` elem törlése (`unban`, `gateway.py:3202-3206`; `unban_all`) | Nem szükséges | `admin_fail2ban_changed` | A régi grant nem áll vissza; újra kell engedélyezni | PASS |
| M23. Automatikus login-tiltás | `on_ban` → `revoke_ip` (`gateway.py:6727-6728`) | `banned_v4` timeouttal | Igen | `fail2ban_ban`; `login_failed` | Igen | PASS |
| M24. Automatikus drop-tiltás | `_on_drop` → `record_drop` → `on_ban` → `revoke_ip` (`gateway.py:6675`, `:6727-6728`) | `banned_v4` timeouttal | Igen | `fail2ban_ban` | Igen | PASS |
| M25. CLI `fail2ban ban/unban/unban-all` | A démonon a vezérlőcsatornán a futó `Fail2ban` példányt hívja (`server.py:4759-4768`), így a ban `on_ban` → `revoke_ip` (`:3826-3831`); helyi példány csak akkor, ha nincs élő démon (`:4412-4468`) | `banned_v4` írás/törlés; a daemon-úton grant- és conntrack-visszavonás is | A daemon-úton igen; helyi módban nincs élő munkamenet | `fail2ban_ban` / `fail2ban_unban`, `cli_*` | A daemon-úton igen; helyi módban nincs élő munkamenet | PASS |
| M26. Küszöb-, mérőszám- és időablak-beállítás | Nincs közvetlen munkamenet-hatás; a három jelzés külön kapcsolható: sikertelen belépések (`enabled`), eldobott csomagok (`drop_count_enabled`) és különböző célportok (`drop_ports_enabled`). A belépés kikapcsolása csak a `source != "drop"` automatikus tiltásokat oldja fel, a két drop-mérőszám együttes kikapcsolása csak a `source == "drop"` tiltásokat; a kézi tiltások mindig megmaradnak (`fail2ban.py:1075-1210`). A küszöbök nem lehetnek 0-k: a `drop_max`/`drop_ports` 0 értékét a `validate_config` elutasítja, a mentett régi 0-t a betöltés migrálja (a mérőszám kikapcsol, a küszöb alapértékre áll). A kikapcsolt mérőszám nem számol, nem tárol eseményt és nem tilt; a meglévő tiltásokat a saját kapcsoló kikapcsolása nem érinti. | `banned_v4` feloldás; hiba esetén a konfiguráció változatlan, a feloldott tiltások pontos hátralévő idővel visszaállnak | Nem | `admin_fail2ban_changed`, `fail2ban_bans_released`; hiba esetén `fail2ban_bans_release_failed` | Nem | PASS WITH CAVEAT (F9 residual: az orphan sor és a rollback best-effort) |
| M27. Tiltáslista-betelés (MAX_BANS) | Nincs közvetlen munkamenet-hatás | A legrégebbi bejegyzés memóriarekordja és kernel-eleme is törlődik; hiba esetén korlátos orphan sor és újrapróbálkozás (`fail2ban.py:844-878`, `:309-352`) | Nem | `fail2ban_ban_evicted` (`kernel_released`), `fail2ban_ban_evict_failed` | Nem | PASS WITH CAVEAT (F9 residual: az orphan sor best-effort) |

### 3.5. Beállítások és életciklus

| Művelet | Érintett munkamenet és felderítés | nft elem/halmaz | conntrack | Portál/audit | Újraengedélyezés | Állapot |
|---|---|---|---|---|---|---|
| M28. Pre-auth / blokk beállítás létrehozása, módosítása, törlése, kapcsolása | Nincs session-visszavonás: a blokk minden grant előtt fut, a pre-auth nem grant | `preauth`, `block`, `preauth_nat`, `block_nat` láncok cseréje egyetlen tranzakcióban (`replace_custom()`, `gateway.py:2845-2871`); hibás beállításfájl esetén a pre-auth ürül, a blokk utolsó ismert jó tartalma megmarad (`:6904-6923`, `:6948-6957`) | Nem szükséges: a blokk a conntrack eredeti tuple-jára illeszkedik | `admin_settings_changed`; hiba esetén 503 és rollback (`:6959-6999`) | Nem; a blokk azonnal érvényes | PASS |
| M29. Regisztráció engedélyezése / oldalnév | Nincs | Nincs | Nincs | `admin_settings_changed` | Nem | PASS |
| M30. Admin általi munkamenet-lezárás | Egy `sid` (`terminate()`, `gateway.py:6613-6630`) | Az adott munkamenet grantjei | Igen | `admin_session_terminated`; a saját munkamenet nem zárható le | Igen | PASS |
| M31. Kilépés | Az aktuális munkamenet (`logout()`, `gateway.py:6592-6612`) | A munkamenet grantjei | Igen | `session_ended` / `access_revoked` | Igen | PASS |
| M32. Természetes lejárat | A reaper a lejárt munkamenetet törli (`gateway.py:6767-6812`) | A lejárt grantek; a kernel TTL ettől függetlenül is töröl | Igen | `session_expired` | Igen | PASS |
| M33. Azonos IP-s új belépés | A régi munkamenet és grantjei; hiba esetén mindkettő eldobódik (`gateway.py:6211-6285`) | A régi grantek | Igen | `session_replaced`, `access_revoked` | Igen | PASS |
| M34. Újraengedélyezés más szabályra/szabályokra | A régi és az új unió különbsége (`_subtract_grants`, `gateway.py:5818-5886`); a távozó elemek pontos visszavonása (`:6506-6535`), hiba esetén a munkamenet megszűnik és nincs új grant; siker esetén az új unió kiadása (`:6542`) | Távozó elemek `revoke_exact`-tel, új unió `timeout`-tal | Célzott `conntrack_flush_removed()`; teljes IP-ürítés csak üres maradéknál (`:6563-6566`) | `access_granted` / `access_modified` (`rules`, `rule_labels`, `rule_count`, `removed_rules`); hiba esetén `firewall_error` (503) | Csak hiba után | PASS |
| M35. Indulás, újraindítás, összeomlás | Nincs perzisztált munkamenet; lásd az 5. szakaszt | Dinamikus halmazok ürítése vagy egyeztetése; stale csak kifejezett opt-innal | Induláskor nincs globális ürítés | `service_start` / `service_stop` | Igen | PASS WITH CAVEAT (összeomlás után a régi grantek a TTL-ig élhetnek) |
| M36. `.env` változás (TTL, interfészek, PORT) | A futó munkamenetek érintetlenek maradnak; lásd az 5.3. szakaszt | A sablon újrarenderelése és betöltése restartot igényel | Nem automatikus | Nincs automatikus esemény | Igen, restart után | PASS (F10 termékdöntés: a fenntartott port mindig a literál 8100) |

## 4. Halmazok és TTL-ek

Minden timeoutos halmazba kerülő elem explicit `timeout`-tal kerül be:
`_bind_mac_locked()` (`gateway.py:3054-3057`), `grant_all()` (`:3178-3183`),
`ban()` (`:3197-3200`) és `sync_bans()` (`:3214-3220`). A `host_service_*`
halmazok nem timeoutosak; a normál szinkron csak hozzáad
(`:3313-3353`), a `flush()` pedig kihagyja őket (`:3633-3636`).

| Halmaz | Típus és méret | Timeout | Író | Törlő | Elem-TTL | Korai eltávolítás | Lejárat után |
|---|---|---|---|---|---|---|---|
| `allowed_v4` | `ipv4_addr`, 4096 | `flags timeout` | `grant_all()` teljes hozzáférésnél | `revoke_all()` mindig, `deny()`, `flush()` | explicit `timeout {ttl}s` | visszavonás, tiltás, blokk, lejárat | kernel törli; a forward drop |
| `allowed_tcp` | `ipv4_addr . inet_service`, 16384 | timeout | `grant_all()` forward TCP | `revoke_all()` (grant vagy `discover`), `deny()`, `flush()` | explicit | visszavonás, lejárat | kernel törli; drop |
| `allowed_udp` | `ipv4_addr . inet_service`, 16384 | timeout | `grant_all()` forward UDP | `revoke_all()`, `deny()`, `flush()` | explicit | visszavonás, lejárat | kernel törli; drop |
| `allowed_input_tcp` | `ipv4_addr . inet_service`, 16384 | timeout | `grant_all()` input TCP | `revoke_all()` mindig IP-re szűrve, `flush()` | explicit | visszavonás, lejárat | kernel törli; az input established őr zár |
| `allowed_input_udp` | `ipv4_addr . inet_service`, 16384 | timeout | `grant_all()` input UDP | `revoke_all()` mindig IP-re szűrve, `flush()` | explicit | visszavonás, lejárat | kernel törli; az input established őr zár |
| `allowed_icmp` | `ipv4_addr`, 4096 | timeout | `grant_all()` ICMP-nél | `revoke_all()` mindig, `flush()` | explicit | visszavonás, lejárat | kernel törli; drop |
| `client_mac` | `ipv4_addr . ether_addr`, 4096 | timeout | `_bind_mac_locked()` a `grant_all()`-ból, csak LAN-on | `_unbind_mac_locked()` (`:3061-3070`), `revoke_all()` (`:3309-3310`), `flush()` | explicit | visszavonás, MAC-kötés megszűnése, lejárat | kernel törli; a MAC-drop szabály csak LAN-on fut |
| `banned_v4` | `ipv4_addr`, 4096 | timeout | `ban()` (`:3197-3200`), `sync_bans()` (`:3214-3220`) | `unban()` (`:3202-3206`), `unban_all()`, `flush()` | explicit; a `sync()` a hátralévő időt egész másodpercre vágva adja meg, legalább 1 mp | feloldás, lejárat | kernel törli; a tiltás megszűnik |
| `host_service_tcp` | `inet_service`, 65536 | nincs | `sync_host_ports()` csak hozzáad (`:3313-3353`) | csak `prune_host_service_ports()` (`:3546-3628`), hivatkozás és élő conntrack nélkül; a `flush()` kihagyja | nincs | prune, csak a két feltétellel | örökre megmarad; csak szigorít, nem ad grantet |
| `host_service_udp` | `inet_service`, 65536 | nincs | `sync_host_ports()` csak hozzáad (`:3313-3353`) | csak `prune_host_service_ports()` (`:3546-3628`), hivatkozás és élő conntrack nélkül; a `flush()` kihagyja | nincs | prune, csak a két feltétellel | örökre megmarad; csak szigorít, nem ad grantet |

A `sync()` a hátralévő időt `int(until - now)` értékkel adja át, a `max(1, ...)`
csak alsó korlát; a lejárt rekordokat kihagyja (`fail2ban.py:1058-1100`). A
`sync_bans()` a kapott TTL-t `max(1, int(ttl))`-ként írja a kernelbe
(`gateway.py:3220`); ez nem hosszabbítja meg a tiltást. A lejárt tiltásokat a
`snapshot()` a memóriából is törli (`fail2ban.py:1107-1113`), a betöltéskor
pedig a `_parse_record()` dobja el (`:478-479`).

A munkamenet lejáratakor a reaper a zár alatt visszavonja a granteket; ha az
IP-hez nem maradt aktív munkamenet, a `revoke_all()` a `client_mac` elemet is
törli (`gateway.py:3372-3373`), részleges esetben pedig a `_subtract_grants()`
csak a nem átfedő elemeket törli (`:5818-5886`): a távozó `full` csak azonos
irányú aktív `full` esetén maradhat el, a nem-`full` távozó részeket aktív
`full` mellett is pontos törlésre adja vissza, hogy később ne bukkanjanak
fel újra. A `host_service_*` prune csak
sikeres szinkron után fut, és a hibája nem rontja el a védőhalmaz
egészségét (`:6651-6666`); ha az nft-listázás vagy a conntrack nem elérhető,
egyetlen port sem törlődik.

## 5. Indulás, újraindítás, összeomlás

### 5.1. `HV_FLUSH_ON_START` és a kapcsolódó kapcsolók

| Helyzet | Entrypoint viselkedés | Gateway viselkedés | Eredmény | Állapot |
|---|---|---|---|---|
| Nincs beállítva, `1`, `true`, `yes`, `on` | `flush_on_start=1`; a dinamikus halmazok ürítése a `host_service_*` kivételével (`docker/entrypoint.sh:28-41`, `:328-343`) | `_env_bool()` (`gateway.py:72-80`); `_startup_flush_mode()` `flush` (`:83-99`); `_startup_flush()` ürít (`:6773-6822`) | Tiszta indulás; minden régi grant eltűnik | PASS |
| `0`, `false`, `no`, `off` | A kapcsoló kikapcsolva, de alapból **egyeztetés** történik: a dinamikus halmazok ürítése (`entrypoint.sh:334-343`) | `_startup_flush_mode()` `reconcile` módot ad, és ürít (`gateway.py:95-99`, `:6815-6820`) | Az árva grantek nem maradnak meg | PASS |
| Érvénytelen érték | Az alapértelmezés `1` (`entrypoint.sh:28-41`) | Az alapértelmezés `True` (`gateway.py:72-80`) | Tiszta indulás | PASS |
| `0` és `HV_ALLOW_STALE_GRANTS_ON_START=1` | Kifejezett, nem biztonságos opt-in: a flush kimarad (`entrypoint.sh:331-332`) | `stale_allowed`: a flush kimarad, hangos napló (`gateway.py:6790-6797`) | A régi grantek a kernel TTL-ig, akár 30 napig életben maradhatnak munkamenet nélkül | PASS WITH CAVEAT (nem biztonságos opt-in; N5 javítva) |
| Ürítési hiba | `die`, az indulás leáll (`entrypoint.sh:340-341`) | `FirewallError` esetén napló, audit, kivétel; az indulás leáll (`gateway.py:6800-6814`) | Fail-closed | PASS |
| Portálfolyamat összeomlása | A konténer `restart: unless-stopped` (`docker-compose.yml:15`); natív módban `Restart=on-failure` (`deploy/hatarvedelem.service:39`) | A munkamenetek elvesznek; a grantek a kernelben a TTL-ig megmaradnak | Az újraindulásig a régi grantek munkamenet nélkül érvényesek | PASS WITH CAVEAT (TTL-biztonsági háló) |
| Host újraindítása | A kernel állapota törlődik; a `hatarvedelem-firewall.service` tölti be a sablont (`deploy/hatarvedelem-firewall.service:18-21`) | A portál induláskor ürít, majd újratölti a fail2ban-t, a host portokat és a beállításokat | Tiszta állapot | PASS (futásidejű feltevés: a unitok engedélyezve vannak) |
| `HV_SKIP_FIREWALL=1` | A sablon betöltése, a Docker-guard és a watchdog kimarad (`entrypoint.sh:392-394`); az `env_bool` minden igaz alakot elfogad | A portál nft-hívásai továbbra is lefutnak; ha a tábla hiányzik, a műveletek hibára futnak | Nincs fail-closed garancia, ha a tábla nincs betöltve | PASS WITH CAVEAT (csak fejlesztői/veszélyes opt-in; N3 javítva) |

A `HV_FIREWALL_WATCHDOG` (compose `:123`; `entrypoint.sh:244`) a tűzfal-figyelő
ki-/bekapcsolása; `0` esetén a watchdog nem fut. A `HV_SKIP_FIREWALL` szintén
`env_bool`-ként értelmeződik (`entrypoint.sh:392-394`), nem csak a pontos
`"1"`-et fogadja el.

### 5.2. Mit egyeztet induláskor, és mit nem

- **Ürít:** `allowed_v4`, `allowed_tcp`, `allowed_udp`, `allowed_input_tcp`,
  `allowed_input_udp`, `allowed_icmp`, `client_mac`, `banned_v4`
  (`entrypoint.sh:336-338`; `gateway.py:3630-3653`).
- **Nem ürít:** `host_service_tcp`, `host_service_udp` (add-only) és a
  `breakglass` lánc (`deploy/hatarvedelem-firewall.service`).
- **Újratölt:** `fail2ban.sync()` a mentett tiltásokkal (`gateway.py:6876`,
  `fail2ban.py:1058-1100`); `sync_host_ports()` a perzisztált input portokkal
  (`gateway.py:6854`, `:6576-6666`); `_apply_custom_settings()` a
  pre-auth/blokkal (`:6896-6946`).
- **Nem perzisztál:** munkamenetek, grantek, conntrack. Induláskor nincs
  globális conntrack-ürítés; a forward a halmazilleszkedés miatt zár, az
  inputot a `host_service_*` őr védi. Ha a `sync_host_ports()` meghiúsul,
  az indulás nem áll le, csak naplóz és auditál; az új host-engedélyek
  fail-closed módon 503-mal zárva maradnak, amíg a következő `authorize()`
  egyszeri újrapróbálkozása sikeres nem lesz (`gateway.py:5990-6006`,
  `:6561-6574`). Egy már meglévő host-kapcsolat az általános
  `ct state established,related accept` szabályon (`nft:418`) át addig
  életben maradhat, amíg a port be nem kerül az őrhalmazba; ezért a sync
  hibáját az adminnak mielőbb rendezni kell.

### 5.3. `.env` változások

A környezeti változókat a folyamat importáláskor olvassa egyszer; a `.env` módosítása a futó folyamatra nem hat.

- **TTL:** `HV_SESSION_TTL`, `HV_MIN_TTL`, `HV_MAX_TTL`, `HV_AUTH_TTL`
  (`gateway.py:142-155`). A meglévő `expires` nem változik; az új belépések
  és `authorize()` hívások használják az újat; a szabály-TTL-ek a
  `rules.json`-ban vannak.
- **Interfészek:** `HV_LAN_IF`, `HV_WAN_IF`, `HV_LAN_NET`,
  `HV_PORTAL_NET`; a sablont az entrypoint rendereli
  (`entrypoint.sh:119-169`), a MAC-kötés importáláskor dől el
  (`gateway.py:244-260`). Váltás csak sablon-újratöltéssel és restarttal
  érvényesül; a régi granteket az induláskori flush tünteti el.
- **PORT:** a `__PORT__` helyőrzőbe és a HTTP-kötésbe kerül
  (`entrypoint.sh:124-125`, `:166-167`; `gateway.py:138`); átállítása
  restartot és nft-újratöltést igényel. **F10 termékdöntés:** a fenntartott
  port a `PORT` értékétől függetlenül mindig a literál 8100
  (`gateway.py:1272-1290`); az input accept is a 8100-at zárja ki
  (`nft:444-445`). Ez nem hiba, hanem elfogadott tervezési döntés: a 8100
  marad az egyetlen fenntartott port akkor is, ha a portál más porton
  hallgat. A `PORT != 8100` beállítás ezért nem ajánlott.
- **Miért kell restart és flush:** a grantek csak a kernelben élnek;
  újrainduláskor a munkamenet-tár kiürül, a kernel elemei viszont a TTL-ig
  megmaradnának, ezért az induláskori flush kötelező.
- **Compose-whitelist:** a `HV_ALLOW_STALE_GRANTS_ON_START` átkerül a
  compose-ba (`docker-compose.yml:91-94`) és a `.env.example` dokumentálja
  (`:155-158`); a `HV_FIREWALL_WATCHDOG` (`docker-compose.yml:123`;
  `.env.example:159`) és a `HV_SKIP_FIREWALL` (`docker-compose.yml:124`;
  `.env.example:164`) szintén elérhető. Natív systemd módban a unit nem
  olvassa a `.env`-et, a `Environment=` sorokat kell módosítani
  (`deploy/hatarvedelem.service:16-36`). N5 javítva.

## 6. Megállapítások (F1–F11)

A státusz a kiinduló hibát és a végleges, 2026-10-20-i állapotot mutatja.
Az F1–F9 és F11 `FIXED`; az F10 termékdöntéssel elfogadott, nem hiba.

| ID | Súlyosság | Állapot | Egy soros hatás | Hivatkozás |
|---|---|---|---|---|
| F1 | High | FIXED | A sikertelen visszavonás korlátozott (4096) sorba kerül, a takarítószál a munkamenet-zár alatt, növekvő várakozással újrapróbálja; részleges visszavonáskor a `_subtract_grants()` csak a maradó munkamenet által nem igényelt elemeket törli, a discovery csak munkamenet nélkül fut. | `gateway.py:5639-5733`, `:5818-5886`, `:5887-5929`, `:6059-6207`, `:6728-6766`; M3–M7, M9–M10, M14, M30–M33 |
| F2 | High | FIXED | Az entrypoint és a gateway is `env_bool`-ként értelmezi a `HV_FLUSH_ON_START`-ot; `0` esetén alapból biztonságos egyeztetés (reconcile) történik, stale csak kifejezett opt-innal maradhat, az ürítési hiba pedig leállítja az indulást. | `gateway.py:72-99`, `:6773-6822`; `docker/entrypoint.sh:28-41`, `:328-343`; M35 |
| F3 | Medium | FIXED | Újraengedélyezésnél a régi grant visszavonásának hibája eldobja a munkamenetet, nem ad új grantet, és `FirewallError` (503) jön; a hiba a pending sorba is bekerül. | `gateway.py:6506-6535`; M34 |
| F4 | Medium | FIXED | A blokk ugrás a forward és az input láncban feltétel nélküli, a blokk a conntrack eredeti tuple-jára illeszkedik (válaszirány és WAN/DNAT is), a `block_nat` pedig LAN-only. | `nft:229`, `:337`, `:465-466`; `gateway.py:2765-2785`; M28 |
| F5 | Medium | FIXED | A `host_service_tcp/udp` mérete 65536, így nem telhet meg; a normál sync add-only, és a biztonságos prune csak hivatkozás nélküli, élő conntrack nélküli portot töröl; ha az nft-listázás vagy a conntrack nem elérhető, semmit nem töröl. | `nft:80-94`; `gateway.py:3313-3353`, `:3546-3628`, `:6654-6666`; 5.2. szakasz |
| F6 | Medium | FIXED | A CLI-módosítások a vezérlőcsatornán a démonhoz mennek; ambigus válasz vagy élő démon mellett nincs helyi fallback, helyi írás csak élő démon nélkül történik. A démon `user del` a csoporttagságot is törli, a helyi törlés szintén. | `server.py:4420-4468`, `:4517-4694`, `:4697-4849`; `:3685-3847`; M18–M20, M25 |
| F7 | Medium-Low | FIXED | A tiltást a munkamenet-ellenőrzés, a belépés és a `/api/access` is ellenőrzi; a tiltott IP a meglévő munkamenetét sem használhatja, az access pedig vissza is vonja. | `server.py:529-537`, `:1661-1671`, `:2428-2448`; M23–M24 |
| F8 | Low | FIXED | A hibás `client_mac` JSON `FirewallError`-t ad (nem üres listát), az `_unbind_mac_locked()` pedig nem-LAN címnél is törli a meglévő/ismert MAC-elemet. | `gateway.py:2939-3000`, `:3061-3070`; 4. szakasz |
| F9 | Low | FIXED | A tiltáslista-betelés felszabadítja a kikerülő bejegyzés kernel-elemét (hiba esetén korlátos, memóriabeli orphan sorral újrapróbálja); a `sync()` a pontos hátralévő TTL-t adja; a `configure()` hiba esetén változatlan konfiguráció mellett visszaállít. Residual: az orphan sor és a rollback továbbra is best-effort. | `fail2ban.py:844-878`, `:309-352`, `:943-1055`, `:1058-1100`; `tests/test_fail2ban_consistency.py`; M26–M27 |
| F10 | Low | ACCEPTED BY DESIGN | A fenntartott port termékdöntés szerint mindig a literál 8100, függetlenül a `PORT` értékétől; a host-port validáció és az input accept is a 8100-at használja. Ez nem hiba, hanem tudatos döntés; a `PORT != 8100` ezért nem ajánlott. | `gateway.py:138`, `:1272-1290`; `nft:444-445`; M36 |
| F11 | Low | FIXED | A pre-auth/blokk láncok cseréje egyetlen nft-tranzakcióban történik (`replace_custom()`); nincs köztes, blokk nélküli állapot, és hibás beállításfájl esetén a pre-auth ürül, a blokk utolsó ismert jó tartalma megmarad. | `gateway.py:2845-2871`, `:6904-6923`, `:6948-6957`; M28 |

### 6.1. A vizsgálat során talált további eltérések (nem F1–F11)

- **N1 (Medium) — FIXED:** az admin felhasználó-módosítás a jelszó, metadata
  és csoporttagság írása előtt visszavonja a munkameneteket
  (`server.py:2958-2962`); ha a jelszó írása után későbbi lépés hibázik, a
  jelszó visszaáll (`:2984-2991`). Teszt:
  `test_admin_update_failure_revokes_and_restores_password`
  (`tests/test_gateway.py:6761`).
- **N2 (Medium) — FIXED:** a CLI `user del` mind a démonon
  (`server.py:3762`), mind a helyi (démon nélküli) módban (`:4633-4636`)
  törli a csoporttagságot, ugyanúgy, mint a HTTP törlés (`:3081`). Teszt:
  `test_cli_local_delete_removes_group_membership`
  (`tests/test_gateway.py:6836`).
- **N3 (Low) — FIXED:** a `HV_SKIP_FIREWALL` az `env_bool`-t használja
  (`docker/entrypoint.sh:392-394`), ezért a `true`, `yes`, `on` alakokat is
  elfogadja.
- **N4 (Low) — FIXED, residual:** a `logout()`, `terminate()`,
  `revoke_user()`, `revoke_user_rules()`, `revoke_rule()`, `revoke_rules()`,
  `revoke_ip()`, `reap_once()`, `validate()` és a
  `_retry_pending_revocations()` a zár alatt hívja a tűzfalat
  (`gateway.py:6592-6612`, `:6613-6630`, `:6631-6663`, `:6664-6682`,
  `:6683-6703`, `:6704-6727`, `:6728-6766`, `:6767-6812`, `:6286-6350`,
  `:6059-6207`). A `validate()` lejárati/IP-váltási visszavonása már a
  munkamenet-törléssel azonos zár alatt fut. Maradék: a `shutdown()`
  (`:6837-6855`) a munkamenet eltávolítása után, a zár nélkül hívja a
  tűzfalat; ez elérhetőségi maradék, mert egy közben engedélyező új
  munkamenet azonos portjait a régi visszavonás törölheti.
- **N5 (Low) — FIXED:** a `HV_ALLOW_STALE_GRANTS_ON_START` bekerült a
  compose whitelistjébe (`docker-compose.yml:91-94`) és a `.env.example`
  dokumentálja (`:155-158`); compose-ban `.env`-ből elérhető.

## 7. Tesztek és lefedettség

### 7.1. Unit tesztek

- `tests/test_revocation.py` (29 teszt): `PendingRevocationTests` (`:212`),
  `DiscoveryTests` (`:575`), `StartupFlushTests` (`:622`),
  `EntrypointFlushParsingTests` (`:722`), `EntrypointBooleanFlagsTests`
  (`:782`). Lefedi a visszavonási sort, a részleges grant-kivonást, a
  discovery-t, az indulási döntésmátrixot és az entrypoint `env_bool`
  értelmezését.
- `tests/test_revocation_lock_scope.py` (12 teszt): `LockScopeTests` (`:151`),
  `PartialGrantTests` (`:195`), `FullRevokeTests` (`:257`),
  `RetryOutsideLockTests` (`:286`). A zártartományt, a `validate()` lejárati
  visszavonását, a részleges visszavonást és a soron kívüli újrapróbálkozást
  ellenőrzi.
- `tests/test_host_service_guard.py` (17 teszt): `TemplateCapacityTests`
  (`:178`), `HostPortHealthTests` (`:199`), `HostServicePruneTests` (`:330`).
  Halmazméret, fail-closed guard és biztonságos prune.
- `tests/test_block_generation.py` (15 teszt):
  `ApplyCustomBlockGenerationTests` (`:121`), `InvalidBlockEntryTests`
  (`:331`), `ClearCustomTests` (`:405`), `ReplaceCustomTests` (`:457`),
  `ApplyCustomSettingsTests` (`:565`). Blokk-renderelés, atomikus
  `replace_custom`, hibás beállítás melletti blokkmegőrzés.
- `tests/test_block_precedence.py` (8 teszt):
  `BlockPrecedenceTemplateTests` (`:61`), `ApplyCustomBlockRuleTests`
  (`:246`). A feltétel nélküli blokk-ugrás és a grantok előtti precedencia.
- `tests/test_fail2ban_consistency.py` (8 teszt): `EvictionTests` (`:125`),
  `SyncTtlTests` (`:191`), `ConfigureAtomicityTests` (`:230`). Eviction/orphan
  sor, sync-TTL, configure rollback.
- `tests/test_live_cli.py` (40 teszt): `ControlServerTests` (`:310`),
  `ControlPeerCredentialTests` (`:586`), `ControlStartupTests` (`:621`),
  `CliFallbackTests` (`:719`), `Fail2banRaceTests` (`:965`). A démon
  vezérlőcsatornája, a fallback tilalma ambigus/élő démon esetén, valamint a
  ban/login verseny.
- `tests/test_gateway.py` többes hozzáféréshez kapcsolódó tesztjei:
  `UnionGrantsTests` (`:2752`, 4 teszt), `SubtractGrantsTests` (`:2793`,
  3 teszt), `MultiSelectionTests` (`:2835`, 9 teszt),
  `ConntrackFlushRemovedTests` (`:3223`, 4 teszt), valamint a `HttpTests`
  (`:3501`, 45 teszt) hat többes hozzáférésű tesztje:
  `test_access_multi_rule_union`, `test_access_multi_rule_validation`,
  `test_access_multi_rule_modification_revokes_removed`,
  `test_access_legacy_single_rule_still_works`,
  `test_status_reports_multi_selection` és
  `test_admin_session_listing_shows_multi_selection`. Lefedi az uniót, az
  átfedő portokat, a pontos kivonást, a conntrack iránykezelését, a
  legszigorúbb TTL-t, a részleges revoke-ot, a lejárt munkamenet
  újrakiadásának tiltását, a `revoke_rules` egy menetes működését és a HTTP
  szerződését.
- `tests/test_propagation_multi.py` (7 teszt): `PropagationHttpTests`
  (`:1`) és a közvetlen `SessionManager`-tesztek. A valós felhasználói
  forgatókönyvet fedi le: a gyűjtő a kiválasztás **második** eleme, a tag
  szerkesztése után csak a gyűjtő választása tűnik el, a többi választás és
  a lejárat megmarad; a tag két gyűjtőben van, de csak az egyik van
  kiválasztva; a gyűjtő és a tag egyszerre kiválasztva egy menetben tűnik el;
  újraengedélyezés a módosítás után az új definíciót adja; a közös input 22
  nem törlődik és nem kap conntrack-ürítést; a vegyes irányú gyűjtő mindkét
  pontos halmaza tisztul. Mind a 7 teszt OK.
- `tests/test_gateway.py` többi említett osztálya: `AdminHttpTests`
  (`:7026`, 50 teszt), benne
  `test_admin_update_failure_revokes_and_restores_password` (`:7604`) és
  `test_cli_local_delete_removes_group_membership` (`:7679`); továbbá
  `FirewallTests` (`:351`), `UserStoreTests` (`:1283`), `SessionTests`
  (`:2178`), `RuleGroupStoreTests` (`:5628`), `TotpCliTests` (`:9942`),
  `CliAuditTests` (`:10077`), `Fail2banTests` (`:12069`),
  `DropBanWiringTests` (`:12475`), valamint az entrypoint-tesztek (`:11928`,
  `:11955`, `:11971`, `:11995`).

A teljes csomag a végleges munkafán: **563 teszt, OK** (2026-10-21).

### 7.2. Élő VM-tesztek

A `tests/e2e_vm.py` a végleges, kapuzott forgatókönyv-mátrixot tartalmazza; a
kapuk a `:64-68` sorokban vannak (`HV_E2E_LONG`, `HV_E2E_PENDING`,
`HV_E2E_RESTART`, `HV_E2E_MULTI`).

- **K1. Visszavonási utak** (`scenario_revocation_matrix`, `:1345`): nincs
  külön kapuja; akkor fut, ha az admin API és a forgatókönyv-erőforrások
  elérhetők (`:2739-2755`), különben skip (`:2765-2774`). Lefedi a logoutot,
  az admin terminate-t, a szabály-, gyűjtőtag- és csoportmódosítást, a
  felhasználó letiltását/törlését és a fail2ban-tiltást.
- **K2. Természetes lejárat** (`scenario_natural_expiry`, `:1499`):
  `HV_E2E_LONG` kapu; kikapcsolva skip (`:1511`). A TTL lejártát és a grantek
  eltűnését ellenőrzi.
- **K3. Blokk elsőbbsége** (`scenario_block_precedence`, `:1699`):
  `HV_E2E_PENDING` kapu; kikapcsolva `pending_skip` (`:1702`).
- **K4. Újraindítási mátrix** (`scenario_restart_matrix`, `:2238`):
  `HV_E2E_RESTART` kapu; kikapcsolva skip (`:2241`).
- **K5. CLI-propagáció** (`scenario_cli_propagation`, `:2027`):
  `HV_E2E_PENDING` kapu; kikapcsolva `pending_skip` (`:2030`).
- **K6. Több szabály együttes engedélyezése** (`scenario_multi_access`,
  `:2432`): `HV_E2E_MULTI` kapu; kikapcsolva skip. A szabálypárt a
  `HV_E2E_RULES` adja (`:2143-2149`, alapértelmezés
  `e2e-rev-fwd,e2e-rev-host`). A forgatókönyv a többes uniót, a részleges
  választást és a célzott visszavonást fedi le.

A forgatókönyvek implementálva és kapuzva vannak, de a repóban nincs
bizonyíték arra, hogy a VM-en lefutottak volna; a véglegesítéshez élő
futtatás szükséges. **A K6 élőben még nem futott.**

### 7.3. Hiányzó tesztek (TODO)

- Élő VM-es, portonkénti conntrack fallback teszt (a prune conntrack nélküli
  ága unit szinten fedett).
- A K1–K6 élő VM-es futtatása és az eredmények rögzítése (a K6 a többes
  választás unióját, részleges visszavonását és UI-ját hivatott élőben
  igazolni).

## 8. Több egyidejű hozzáférés (implementált)

**Adatmodell.** A `Session` a kiválasztott szabályok azonosítóit
`rules: tuple[str, ...]`, a teljes választásokat
`rule_parts: tuple[RuleSelection, ...]` mezőkben tárolja
(`gateway.py:5398-5399`); a `rule`/`rule_label` továbbra is az első választás
kompatibilitási nézete (`:6567-6585`). Egy `RuleSelection` a szabály
azonosítóját, címkéjét és grantjeit fogja össze (`:432-443`). A `selections()`
a régi, egy-szabályos munkamenetből is előállítja a választást
(`:5414-5423`), a `snapshot()` pedig a `selected_rules`,
`selected_rule_labels` és irányonkénti `grants` mezőket is kiadja
(`:5433-5460`). A `Session.ports`/`ports.label()` lapított, megjelenítési
nézet marad.

**Unió és TTL.** A `union_grants()` a granteket irányonként (forward/input)
egyesíti (`gateway.py:445-497`): a TCP/UDP portok halmazként, növekvő
sorrendben; az ICMP VAGY-kapcsolattal; a `full` ugyanabban az irányban
elnyeli a TCP/UDP/ICMP részeket; az üres irányok kimaradnak; az eredmény
determinisztikus (forward, majd input). A munkamenet TTL-je nem haladhatja
meg a kiválasztott szabályok legkisebb `max_ttl` értékét; a kérés
elutasításra kerül, nem csonkolódik (`:6398-6413`).

**Engedélyezés és újraengedélyezés.** Az `authorize(token, ip, rules, ttl)`
egyetlen `Rule`-t (régi hívók) vagy nem üres sorozatot fogad
(`gateway.py:6351-6437`). Az azonosítókat az első előfordulás sorrendjében
deduplikálja, minden szabályt validál, majd a régi és az új unió különbségét
(`_subtract_grants`, `:5818-5886`) `revoke_exact`-tel törli a távozó
elemeket, és a `grant_all()`-lal kiadja az új uniót (`:6496-6542`). A
conntrack csak a távozó portokra célzott (`:6563-6566`). Ha a távozó elemek
visszavonása nem sikerül, a munkamenet megszűnik, a régi és az új unió
visszavonása megtörténik, és a HTTP 503-at ad; új grant nem keletkezik
(`:6506-6535`; `server.py:2599-2612`).

**Részleges visszavonás.** A `_remove_selections_locked()`
(`gateway.py:5930-6057`) a megadott szabály-azonosítókat törli a munkamenet
`rule_parts` listájából. Ha marad választás, a munkamenet megtartja az
eredeti lejáratát, a távozó unió pontos elemeit `revoke_exact` törli, a
maradó uniót `grant_all()` újrakiadja (szükséges, mert egy korábbi `full`
grant elfedhette a portelemeket), és a conntrack csak a távozó portokra
célzott (`:6001-6055`). Lejárt munkamenet nem kap vissza semmit: teljesen
eltávolítódik (`:5978-5988`). Ha nem marad választás, a munkamenet
megszűnik. Tűzfalhiba esetén fail-closed: a munkamenet eldobódik, és a
teljes régi unió visszavonása megtörténik (`:6035-6056`). A
`revoke_user_rules(user, rule_ids)` egy felhasználó munkameneteiből csak a
megadott választásokat törli (`:6664-6682`); a `revoke_rules(rule_ids)` a
szabályt és a függő gyűjtőket egy zárolás alatt, egy menetben távolítja el
(`:6704-6727`); a `revoke_rule(id)` a többi hívó számára megmarad
(`:6683-6703`).

**Pontos kivonás.** A `_subtract_grants()` csak akkor hagyja el a távozó
`full` elemet, ha egy aktív, azonos irányú `full` fedi
(`gateway.py:5818-5886`). Az aktív `full` által fedett, nem-`full` távozó
részeket pontos törlésre adja vissza, különben a korábbi
`allowed_tcp/udp/icmp` elemek később újra felszínre kerülhetnének.

**Conntrack.** A `conntrack_flush_removed(ip, removed, remaining)`
(`gateway.py:4052-4184`) csak akkor végez IP-s teljes ürítést, ha a távozó
`full` mellett semmi nem marad engedélyezve. Maradó grant mellett soha nem
teljes ürít; ha bármely maradó rész `full`, a célzott parancsokat kihagyja
(a conntrack irányvak). A port-/ICMP-lefedettséget az összes maradó irány
uniójából számítja. Több mint 16 célzott parancs esetén maradó grant mellett
naplóz és kihagy (`:4132-4141`); csak üres maradék esetén esik vissza teljes
ürítésre.

**HTTP és UI.** A `POST /api/access` a
`{"rules": [azonosítók...], "rule": első, "ttl": N}` alakot fogadja
(`server.py:2521-2536`). A `rules` az irányadó: nem üres lista, amely csak
nem üres sztringeket tartalmaz, deduplikálva, legfeljebb
`MAX_SESSION_RULES = 16` (`server.py:63`, `:381-414`). Minden azonosító feloldása az `authorize()`
előtt történik, így nincs részleges grant (`:2586-2592`). A régi
`{"rule": id, "ttl": N}` továbbra is működik. Az engedélyezett válasz és a
`/api/status` a `selected_rules`, `selected_rule_labels`, `grants` mezőkkel
egészül ki, a régi `rule`/`rule_label`/`grant` mezők megmaradnak
(`server.py:833-853`, `:958`). Az audit `access_granted`/`access_modified`
eseménye a `rules`, `rule_labels`, `rule_count`, módosításkor a
`removed_rules` mezővel egészül ki; a `direction` `mixed` is lehet
(`server.py:2620-2652`). A portál
UI többes kiválasztást, uniós TTL-korlátot és irányonkénti grant-megjelenítést
használ; az admin munkamenetlista a kiválasztott szabályok címkéit mutatja.
A K6 élő forgatókönyv (`tests/e2e_vm.py`, `HV_E2E_MULTI`, `HV_E2E_RULES`)
implementálva van, de a VM-en még nem futott.

**Élő felületi frissítés.** A böngésző engedélyezett munkamenetnél a
30 másodperces `/api/status` pollból frissíti az `auth.rules` katalógust,
nem a belépéskori pillanatképet használja. A módosítás (`access`) nézetben
a `refreshAccessFromStatus()` helyben marad: a `rulesSignature()`
ujjlenyomat változásakor újrarajzolja a szabálykártyákat, a még érvényes,
folyamatban lévő kijelölést megtartja, a módosult vagy eltűnt szabályt
kiveszi a kijelölésből, és ha a szerver a választást visszavonta, kiírja,
hogy az érintett hozzáférést újra kell engedélyezni. A **Módosítás** gomb
megnyitás előtt friss `/api/status`-t kér (`cache: no-store`); hálózati
hiba esetén a gyorsítótárazott pillanatképet használja, de nem navigál el.
A session-nézet a pollban észlelt választásváltozást `sessionRevokedNotice`
üzenettel jelzi, és a következő pollokon is megtartja. A szabály módosítása
tehát a felületen is azonnal látszik, de az új definíció engedélyezése
továbbra is kifejezett, kétfázisú művelet marad.

**Maradék korlátok.** Ezek ismertek és nem szüntetik meg a fenti garanciákat:

1. A `SessionManager._lock` egyetlen globális zár, amely a teljes
   nft/conntrack hívás alatt tartva van; egy lassú vagy beragadt `nft` minden
   munkamenet-műveletet blokkolhat. A 16 parancs/3 mp-es conntrack-korlát
   (`CONNTRACK_REMOVED_LIMIT`, `gateway.py:4049`, `:4132-4141`) enyhíti, de
   nem szünteti meg a kockázatot.
2. `direction="mixed"` esetén a régi, lapított `Session.ports` /
   `ports.label()` audit- és snapshot-címke az input portokat forwardként
   jelenítheti meg; a kényszerítés és a `grants` irányhelyes, az admin UI a
   `grants` mezőt használja (`gateway.py:5425-5432`, `:5433-5460`).
3. A `sync_host_ports()` szűk TOCTOU-ablakot hagy egy újonnan hozzáadott
   input portnál a szabálytár commitja és az őrhalmaz érvénytelenítése
   között; ez csak akkor számít, ha az azt követő sync és a conntrack-tisztítás
   is meghiúsul (`server.py:3345-3357`, `gateway.py:7129-7148`).
4. Teszt-tűzfalakon a `revoke_exact` visszaeshet
   `revoke_all(only_grants=True)`-ra; a produkciós `Firewall` mindig
   rendelkezik `revoke_exact`-tel (`gateway.py:5734-5746`, `:3377-3397`).

A mátrix M3–M7 és M34 sorai a többes választásos modellre érvényesek; az
„Újraengedélyezés” csak akkor kötelező, ha a munkamenetnek nem maradt
választása (vagy a visszavonás fail-closed módon eldobta).

## 9. Nem ellenőrzött futásidejű feltevések

- Az `nft -f` újratöltés a láncokat flusholja, a halmazokat nem, ezért a
  dinamikus elemek elvileg túlélik; ezt nem futtattuk a VM-en.
- A `conntrack -D -s IP` minden forrás-IP-s bejegyzést töröl; a bináris és
  a képesség megléte a telepítéstől függ, hiba esetén csak audit készül
  (`gateway.py:3927-3958`).
- A `DOCKER-USER` guard és a host névtér viselkedése a Docker verziójától
  függ; a kód a `meta mark`-ra és a `DOCKER-USER` láncra támaszkodik
  (`docker/entrypoint.sh:180-239`).
- A systemd unitok engedélyezettsége és a `Restart=on-failure` működése nincs
  ellenőrizve; a nem `host_service_*` halmazok (4096/16384) telítődése sincs
  élőben tesztelve. A `host_service_*` 65536-os mérete unit szinten fedett
  (`tests/test_host_service_guard.py`).
- A többes hozzáférés egyetlen globális `SessionManager._lock`-ja a teljes
  nft/conntrack hívás alatt tartva van; egy lassú vagy beragadt `nft` minden
  munkamenet-műveletet blokkolhat. A 16 parancs/3 mp-es conntrack-korlát
  (`CONNTRACK_REMOVED_LIMIT`, `gateway.py:4049`, `:4132-4141`) enyhíti, de
  nem szünteti meg a kockázatot.
- `direction="mixed"` munkamenetnél a régi, lapított `Session.ports` /
  `ports.label()` audit- és snapshot-címke az input portokat forwardként
  jelenítheti meg; a kényszerítés és a `grants` irányhelyes, az admin UI a
  `grants` mezőt használja (`gateway.py:5425-5432`, `:5433-5460`).
- A `sync_host_ports()` szűk TOCTOU-ablakot hagy egy újonnan hozzáadott
  input portnál a szabálytár commitja és az őrhalmaz érvénytelenítése között;
  ez csak akkor számít, ha az azt követő sync és a conntrack-tisztítás is
  meghiúsul (`server.py:3345-3357`, `gateway.py:7129-7148`).
- Teszt-tűzfalakon a `revoke_exact` visszaeshet
  `revoke_all(only_grants=True)`-ra; a produkciós `Firewall` mindig
  rendelkezik `revoke_exact`-tel (`gateway.py:5734-5746`, `:3377-3397`).
