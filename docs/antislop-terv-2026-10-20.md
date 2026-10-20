# Anti-slop terv — Dropjak portál (2026-10-20)

Státusz: a P0 kör implementálása folyamatban. Az audit a `267a1ce` commit állapotára készült.
A de-slop előtti design backupja: `docs/design-backup-2026-10-20/`, tag: `design/pre-deslop-2026-10-20`.

## Kiindulás

A portál alapja nem slop: a login hangja („Állj!”, „Azonosítsd magad!”), a szerif wordmark, a
kétfázisú captive-portal flow, a valós empty/loading/error állapotok, a táblák és a HU/EN/DE i18n
maradnak. A slop az admin **Drop napló** és **Fail2ban** dashboardra, a mikrotipográfiára és a
pill-rendszerre koncentrálódik.

Mért számok a kiinduló állapotban:

- 151 különböző hex szín a stylesheetben, miközben a `:root` 20 szemantikus tokent definiál.
- 21 font-size érték; 72 deklaráció 12px alatt; 6 wide-tracked uppercase label.
- 12 border-radius érték, 8 dekoratív gradient, 21 box-shadow.
- 10 pill-variáns; a drop táblában minden sor kap `reason-pill`-t.
- 21 hardcode-olt accent szín a JS-ben; a dark-mode chart piros 2.67:1 kontrasztú.
- Inputkeret `--line-strong:#d6d6d2` fehéren 1.46:1; `#8a8a85` szöveg 3.47:1; `#9a9a95` 2.83:1.

## P0 — CSS-only quick winsek (ez a mostani kör)

Cél: a legláthatóbb slop eltávolítása admin flow-, API-, táblázat- és stringváltozás nélkül.

1. **Type scale és 12px alatti szövegek normalizálása.** `--fs-2xs:12px`, `--fs-xs:12.5px`,
   `--fs-sm:13px`, `--fs-md:14px`, `--fs-lg:16px`, `--fs-xl:20px`; a 9–11.5px deklarációk
   cseréje (chart axis 11px maradhat). A 6 uppercase label (`th`, `.ban-label`, `.role-pill`,
   `.stat span`, `.drop-stat > span`, `.drop-filter-field label`) sentence case-re vált.
2. **Lapos felületek.** A drop/fail2ban gradientek helyett `var(--soft)` / `var(--card)`; a 3px-es
   dekoratív bal csíkok (`.drop-stat::before`, `.drop-card-head h3::before`,
   `.drop-filter-head b::before`) és a `.drop-dot` glow törlése; a tab/nav active shadowök törlése.
   A card (`:63`) és a language menu (`:205`) elevation marad.
3. **Kontraszt és focus ring.** `--muted-strong:#6b6b66`; a `#8a8a85`, `#9a9a95`, `#a6a6a0`
   cseréje; globális `:focus-visible{outline:2px solid var(--blue);outline-offset:2px}`; az
   `outline:none` eltávolítása az inputokról, a `.lang-option`-ról és a `.picker-search`-ről.
4. **Pill-erdő visszavágása.** A táblázatbeli `.pill`, `.reason-pill`, `.role-pill`,
   `.drop-filter-count`, `.fw-verdict`, `.fw-legend span` sima szöveg + színes dot; a `.chip`
   4px radius, 12px font; a `.status-pill` marad az egyetlen page-level badge (12.5px).
5. **Fail2ban stat grid.** `.drop-stats` `repeat(auto-fit,minmax(150px,1fr))`, hogy az ötödik
   kártya ne lógjon egyedül.
6. **Captcha „HV / ellenőrzés” brand levétele.** A `.captcha-brand` CSS és markup törlése.
7. **Tap targetek és iOS zoom.** `.theme-toggle` 40px (coarse pointeren 44px); `button.small`,
   `td.actions button` `min-height:32px` (coarse pointeren 44px); mobilon az inputok 16px-esek.

## P1 — következő kör (még nincs implementálva)

- Stat wall kiváltása (Drop: 1–2 valódi metrika + státuszsor; Fail2ban: státusz + tiltott IP-k).
- Szemantikus paletta: a 21 hardcode-olt accent tokenre; max. 2–3 alapszín + accent.
- Theme-aware chart: CSS token a fill-nek, 3:1 szegmenskontraszt, időablak a címben.
- Empty state differenciálás: első futás vs. „szűrőre nincs találat” + szűrőtörlés action.
- Hosszú súgók progressive disclosure (`<details>`), rövidített copy.
- ARIA: rule card `aria-pressed`/radio szemantika, üres `<th>` accessible név, tablist/tabpanel.
- Naming: „Beállítások” tab vs. „Tűzfal testreszabása” heading egységesítése; „Repeat new password”.
- Field boundary token (3:1), teljes 44x44 tap target pass, 200% zoom teszt.

## P2 — nagyobb redesign (később)

- Teljes tokenrendszer (szín, type, spacing, radius, elevation, chart paletta) + `docs/design-direction.md`.
- Drop log decision-first redesign; Fail2ban redesign; firewall vizuális nézet egyszerűsítése.
- Admin navigáció csoportosítása; identitás-finomítás.

## Ne változzon

- A szerif „dropjak” wordmark és a gyémánt-vonal motívum.
- A HU/EN/DE architektúra (`data-i18n`, `tr()`, szótárak, zászlós nyelvváltó).
- A light/dark tokenpár és a rendszer-preferenciát követő toggle.
- A kétfázisú captive-portal flow és a fail-closed üzenetek.
- A ban képernyő Wojak illusztrációja és az „Állj!” voice.
- A rule cardok szerkezete, a táblák + sticky header + mobil vízszintes scroll stratégia.
- A valós empty/loading/error állapotok, a live countdownok, a szemantikus státuszszínek.
- A monospace használat IP-hez, időbélyeghez, portokhoz, nft szabályhoz.
- A meglévő konkrét copy (nincs hype, fake statisztika, emoji).

## Acceptance checklist a P0 körhöz

- Login, ban, access, session, password nézetek 360, 390, 768, 1024, 1440px-en; nincs page-level
  vízszintes scroll; a táblák a saját wrapperükben scrolloznak.
- HU/EN/DE nyelváltás után minden statikus és dinamikus címke helyes.
- Light és dark téma; a focus ring minden interaktív elemen látható, legalább 3:1.
- Keyboard: Tab a loginen, captcha Enter/Space, rule cardok, TTL, gombok, admin nav, formok;
  Escape a language menüben; nincs focus trap.
- Admin tabok végig: Users, Groups, Rules, Sessions, Firewall, Drops, Fail2ban, Logs, Settings.
- Konzolhiba nincs; a hálózati kérések payloadja változatlan.
- Kontraszt spot check: 12px szöveg 4.5:1, border/focus/chart 3:1.
- 200% zoom 390px-en; semmi nem csúszik egymásra.
- `python3 -m unittest discover -s tests -p 'test_*.py'` zöld (169 teszt).
