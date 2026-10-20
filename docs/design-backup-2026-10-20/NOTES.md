# Design pillanatkép – 2026-10-20

**Dátum:** 2026-10-20
**Commit:** `267a1ce` – „Fix manual fail2ban ban visibility and admin session races"
**Állapot:** a pillanatkép készítésekor élesben futó (deployed) verzió

## Cél

De-slop előtti design pillanatkép / restore point. A cél az, hogy a látványterv átalakítása előtti UI-állapot pontosan visszaállítható legyen.

## Tartalom

| Fájl | Méret |
| --- | --- |
| `index.html` | 327 022 bájt (kb. 319,4 KiB) |
| `icon.png` | 122 957 bájt (kb. 120,1 KiB) |
| `blocked.png` | 1 346 593 bájt (kb. 1,28 MiB) |
| `README.md` | 14 849 bájt (kb. 14,5 KiB) |

Az `index.html` relatív útvonalon hivatkozik az `icon.png` és `blocked.png` fájlokra, ezért a három fájlnak egy mappában kell maradnia.

A képernyőképek a `screenshots/` mappában találhatók (kizárólag a bejelentkező oldal, bejelentkezés nélküli állapotban).

A pillanatkép csak a UI-fájlokat tartalmazza: a `server.py`, a tesztek, az állapotfájlok és a titkok (`.env`, `.secret`) szándékosan kimaradtak.

## Visszaállítás

A repó gyökeréből:

```bash
cp docs/design-backup-2026-10-20/index.html index.html
cp docs/design-backup-2026-10-20/icon.png icon.png
cp docs/design-backup-2026-10-20/blocked.png blocked.png
```

Vagy a design ág/branch segítségével:

```bash
git checkout design/pre-deslop-2026-10-20 -- index.html icon.png blocked.png
```

Az integritás ellenőrizhető a `SHA256SUMS` fájllal:

```bash
cd docs/design-backup-2026-10-20
sha256sum -c SHA256SUMS
```
