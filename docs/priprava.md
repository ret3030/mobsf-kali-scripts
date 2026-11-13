# Příprava na Android pentest

Co musím umět, než začnu testovat podle android-pentest-guide. Moduly M01 až M20 jsou z `CVUT/postup.md`. Hodiny jsou odhad.

## Co guide předpokládá podle kapitol

| Kapitola guidu | Co musím umět | Modul v postupu |
|---|---|---|
| 0 Setup a Kali | shell, oprávnění, procesy, ssh, adb, VM | M01, M02 |
| 1 Statická analýza | struktura APK, AndroidManifest, čtení Javy/Kotlinu, základ smali, hash a šifry (AES, RSA, špatné režimy), supply chain | M03, M10, M17, mezera A |
| 2 Lokální úložiště | souborový systém a práva na Linuxu, SQLite, Android Keystore, backup | M01, M06, M09 |
| 3 Dynamická analýza | procesy, paměť, ladění, základ ARM, Frida (JavaScript), komponenty a Intenty | M07, M09, mezera A |
| 4 Síť a API | TCP/IP, DNS, HTTP, TLS a PKI, certificate pinning, Burp Suite | M04, M10, M11 |
| 5 Logika | autentizace, session, JWT/OAuth, IDOR, autorizace na serveru | M11 |
| 6 Reporting | metodika pentestu, CVSS, právní rámec | M05, M12 |

## Mezery A: věci, které v roadmapě CVUT nejsou

| Téma | Rozsah | Hodiny | Zdroj |
|---|---|---|---|
| Java/Kotlin na úrovni čtení kódu | třídy, rozhraní, výjimky, základy Androidu, čtení dekompilátu v jadx | 15 až 20 | oficiální Kotlin/Java tutoriály, kód z jadx |
| Architektura Androidu | Activity, Service, BroadcastReceiver, ContentProvider, Intent, permissions, sandbox (UID na aplikaci), SELinux, ART | 10 až 12 | MASTG "Android Platform Overview", Android Developers "App fundamentals" |
| JavaScript pro Frida | proměnné, funkce, objekty, callbacky | 6 až 8 | MDN JavaScript Guide, dokumentace Frida |
| Čtení assembleru (ARM, smali) | jen přehledově, důkladně až s M07 a M15 | 4 až 6 | MASTG, smali dokumentace |

## Minimum před prvním testem (60 až 80 h)

| Pořadí | Modul | Rozsah | Hodiny | Odemyká |
|---|---|---|---|---|
| 1 | M01 Linux a shell | celý modul, procvičit na OverTheWire Bandit | 24 | kapitola 0, nutné pro Kali a adb |
| 2 | M04 Počítačové sítě | TCP/IP, DNS, HTTP, TLS | 15 z 32 | kapitola 4 |
| 3 | M10 Aplikovaná kryptografie | symetrické vs. asymetrické šifry, hash, MAC, certifikáty | 15 z 32 | kapitola 1 (poznat špatné krypto) |
| 4 | M06 Databáze | SQLite a SQL injection | 8 | kapitola 2 |
| 5 | Mezery A | Java, architektura Androidu, JavaScript | 31 až 40 | kapitoly 1 a 3 |
| 6 | M11 Webová bezpečnost | HTTP, session, autentizace, Burp | 15 z 32 | kapitoly 4 a 5 |

Po bodech 1 až 5 zvládnu statickou analýzu (kapitoly 0 až 2). Dynamiku (3) a síť (4) po M04 a M10. M07 (C a paměť) a M09 (OS do hloubky) pomáhají, ale k začátku nejsou nutné.

## Pravidla pro praxi

- Testovat jen vlastní nebo záměrně zranitelné aplikace: OWASP MASTG Hacks, UnCrackable Apps, InsecureBankv2, DIVA, OWASP Juice Shop jako backend.
- Cizí aplikace nebo cizí backend jen s písemným povolením.
- Nejdřív emulátor nebo starý telefon s rootem, ne denní telefon.
- Jednu kapitolu guidu projít na jedné cvičné aplikaci a nálezy zapsat ve formátu z kapitoly 6.

## Stav

| Krok | Hotovo |
|---|---|
| M01 | ⬜ |
| M04 (část) | ⬜ |
| M10 (část) | ⬜ |
| M06 (část) | ⬜ |
| Mezery A | ⬜ |
| M11 (část) | ⬜ |
| První test na cvičné aplikaci | ⬜ |
