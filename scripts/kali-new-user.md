# Nový uživatel na Kali místo starého

Postup pro vlastní stroj. Cíl: čistý uživatel s běžnými právy, pod kterým poběží MobSF a emulátor (viz `setup-mobsf.sh`). Příkazy s `STARY` a `NOVY` uprav na skutečná jména.

## 0. Zálohuj, než cokoli smažeš

Smazání uživatele je nevratné. Zkopíruj si z domovského adresáře starého uživatele, co chceš zachovat:

```bash
ls -la /home/STARY                 # projít, co tam je
tar czf ~/zaloha-STARY.tar.gz -C /home STARY
```

Záloha ať leží mimo `/home/STARY` (třeba na externím disku nebo v ownCloudu), jinak zmizí se smazáním.

Co obvykle stojí za zachování:

| Co | Kde |
|---|---|
| SSH a GPG klíče | `~/.ssh`, `~/.gnupg` |
| Projekty, APK, poznámky | podle toho, kam jsi ukládal |
| Konfigurace Burp Suite | `~/.BurpSuite` |
| Shell konfigurace | `~/.zshrc`, `~/.bashrc` |
| Historie scanů MobSF (jen když chceš) | `~/.MobSF` |

Android SDK (`~/Android`) a emulátor **nekopíruj**, nainstalují se znovu skriptem.

## 1. Vytvoř nového uživatele

```bash
sudo adduser NOVY
sudo usermod -aG sudo,adm,dialout,audio,video,plugdev,netdev,users,kvm NOVY
```

Skupina `kvm` je nutná pro rychlý emulátor. Skupinu `wireshark` přidej, jen pokud ji máš nainstalovanou (`getent group wireshark`).

## 2. Přihlas se jako nový uživatel

Odhlas se a přihlas jako `NOVY` (kvůli skupinám nestačí `su`). Ověř:

```bash
whoami
id                  # musí obsahovat sudo a kvm
sudo -v             # funguje sudo?
```

Starého uživatele nemůžeš smazat, dokud je přihlášený.

## 3. Přenes data

```bash
sudo rsync -a /home/STARY/projekty/ /home/NOVY/projekty/
sudo chown -R NOVY:NOVY /home/NOVY
```

Kopíruj výběrově. Celý domovský adresář nekopíruj, přenesl by staré problémy s právy (soubory vytvořené pod `sudo` nebo `root`).

## 4. Nainstaluj nástroje pro nového uživatele

Balíčky z `apt` jsou společné pro celý systém. Pro nového uživatele zbývá to, co se instaluje do domovského adresáře:

```bash
git clone <url tohoto repozitáře> ~/android-pentest-guide    # nebo zkopíruj složku
cd ~/android-pentest-guide
./scripts/setup-kali.sh          # pipx nástroje (frida, objection, semgrep) pro tohoto uživatele
./scripts/setup-mobsf.sh         # MobSF, SDK, AVD
```

Oba skripty spouštěj jako `NOVY`. `sudo` si vyžádají jen u `apt`. Pak odhlas a přihlas (skupina `kvm`) a spusť:

```bash
./scripts/mobsf-dynamic.sh
```

Kontrola vlastnictví:

```bash
ls -la ~/.MobSF ~/tools ~/Android      # vlastník musí být NOVY, ne root
```

## 5. Smazání starého uživatele

Nejdřív uživatele jen **zamkni** a pár dní zkoušej, jestli ti něco nechybí:

```bash
sudo usermod -L STARY
sudo usermod -s /usr/sbin/nologin STARY
sudo pkill -u STARY             # ukonči jeho procesy
```

Až si budeš jistý, smaž ho i s domovským adresářem:

```bash
sudo deluser --remove-home STARY
```

Mimo `/home` zůstat mohou soubory ve `/var/mail` nebo v systémových adresářích. Najdeš je takto:

```bash
sudo find / -xdev -user STARY 2>/dev/null
```

Kdyby `STARY` byl výchozí uživatel `kali`, zkontroluj před smazáním, že nový uživatel má `sudo`. Jinak se z počítače vyzamkneš. Při potížích viz `docs/kali-password-recovery.md`.

## 6. Úklid

Odstraň výchozí heslo `kali`, pokud na stroji zůstane jiný účet s tímto jménem. Změň také výchozí přihlášení MobSF (`mobsf` / `mobsf`) v jeho webovém rozhraní po prvním spuštění.
