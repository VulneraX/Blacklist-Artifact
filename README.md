# Blacklist Artifact

> **Threat Intelligence Blocklist Collection**  
> Kurated dari data empiris T-Pot Honeypot Sensor - untuk penggunaan Blue Team dan SOC
> v0.1
---

## About this Repo

Repository ini merupakan **koleksi terkurasi Indicators of Compromise (IOC)** yang diekstrak secara sistematis dari infrastruktur honeypot T-Pot. Setiap kuartal, data mentah dari sensor honeypot diproses melalui pipeline *Attack Chain Analysis* untuk menghasilkan blocklist yang terklasifikasi, terdeduplikasi, dan siap diimplementasikan pada perangkat pertahanan jaringan.

Dalam konteks *Cyber Threat Intelligence* (CTI), blocklist ini merepresentasikan **tactical intelligence** - artefak teknis yang dapat langsung diterapkan pada firewall, IDS/IPS, SIEM, EDR, dan web proxy untuk mendeteksi atau memblokir aktivitas malicious yang telah terverifikasi melalui observasi langsung pada honeypot sensor.

### Source Data

| Komponen | Detail |
|---|---|
| **Platform** | T-Pot CE (Community Edition) - Telekom Security |
| **Arsitektur** | Manager + Sensor (dual-node deployment) |
| **Honeypot aktif** | 13+ layanan: Cowrie (SSH), Dionaea (SMB), Mailoney (SMTP), Ciscoasa (VPN), Tanner (HTTP), dll. |
| **Data pipeline** | Attack Chain Hourly Aggregate → Elasticsearch 9.2.3 |
| **Index** | `attack-chain-*` (chain records), `logstash-*` (raw events) |

### Methodology

1. **Collection:** Honeypot sensor mengumpulkan seluruh interaksi attacker secara pasif
2. **Correlation:** Pipeline mengkorelasikan events per-IP per-jam menjadi attack chain records
3. **Classification:** Setiap chain mendapat severity berdasarkan stage tertinggi yang dicapai  
4. **Extraction:** Query Elasticsearch mengekstrak semua IP, hash, dan URL per tier
5. **Deduplication:** IP di-assign ke tier tertingginya saja - tanpa duplikasi lintas tier
6. **Documentation:** Setiap release disertai panduan implementasi lengkap

---

## Directory Structure

```
blocklist/
├── README.md                           ← Dokumen ini
│
├── Q1 (March 2026)/                    ← Release pertama: 20 Feb – 21 Mar 2026
│   ├── BLOCKLIST_GUIDE.md              ← Panduan lengkap per-release
│   ├── _stats.json                     ← Statistik JSON (untuk automation)
│   ├── blocklist_ip_critical.txt       ← IP PostExploitation
│   ├── blocklist_ip_high.txt           ← IP Exploitation
│   ├── blocklist_ip_medium.txt         ← IP CredentialAccess
│   ├── blocklist_ip_low.txt            ← IP Reconnaissance
│   ├── blocklist_ip_all.txt            ← Semua IP gabungan
│   ├── blocklist_sha256.txt            ← SHA256 payload hashes
│   ├── blocklist_urls.txt              ← Malicious download URLs
│   ├── file_downloads.csv              ← Seluruh 6.552 file download events
│   ├── file_downloads_ips.txt          ← 1.859 unique downloader IPs
│   ├── file_downloads_by_hash.csv      ← Agregasi download per hash
│   ├── file_downloads_by_ip.csv        ← Agregasi download per IP
│   └── *.csv                           ← Versi CSV dengan metadata
│
├── Q2 (June 2026)/                     ← [Akan datang] April – Juni 2026
├── Q3 (September 2026)/                ← [Akan datang] Juli – September 2026
└── Q4 (December 2026)/                 ← [Akan datang] Oktober – Desember 2026
```

Setiap folder kuartal merupakan **self-contained release** - berisi seluruh file blocklist untuk periode tersebut beserta dokumentasi panduan. File `BLOCKLIST_GUIDE.md` di dalam setiap folder menjelaskan secara mendetail: definisi tier, statistik, distribusi geografis, profil aktor, dan panduan implementasi teknis.

---

## Tier Classification System

Blocklist menggunakan sistem **4-tier** yang memetakan 1:1 dengan stage tertinggi pada attack chain:

| Tier | Severity | Stage | Deskripsi | Rekomendasi |
|---|---|---|---|---|
| **CRITICAL** | Critical | 4-PostExploitation | IP terkonfirmasi melakukan post-compromise: payload download, persistence, privilege escalation | **Block immediately** |
| **HIGH** | High | 3-Exploitation | IP yang aktif mengeksploitasi layanan setelah autentikasi berhasil | **Block** - prioritas tinggi |
| **MEDIUM** | Medium | 2-CredentialAccess | IP melakukan brute-force atau credential stuffing secara aktif | **Block atau rate-limit** |
| **LOW** | Low | 1-Reconnaissance | IP hanya melakukan scanning/probing tanpa serangan aktif | **Monitor** - block opsional |

**Prinsip deduplikasi:** Setiap IP hanya muncul di **satu tier** - tier tertinggi yang teridentifikasi. IP dengan chain PostExploitation DAN CredentialAccess hanya dicatat di tier CRITICAL.

---

## Release History

### Q1 2026 - Release Pertama (Baseline)

| Metrik | Nilai |
|---|---|
| **Periode observasi** | 20 Februari – 21 Maret 2026 (30 hari) |
| **Total unique IP** | **14.550** |
| CRITICAL (PostExploitation) | 1.922 IP |
| HIGH (Exploitation) | 1.824 IP |
| MEDIUM (CredentialAccess) | 1.480 IP |
| LOW (Reconnaissance) | 9.324 IP |
| **SHA256 hashes** | 26 |
| **Malicious URLs** | 9 |
| **Total attack chains** | 45.822 |
| **Total file downloads** | 6.552 |
| **Unique downloader IPs** | 1.859 |
| **Tanggal rilis** | 22 Maret 2026 |

**Temuan kunci Q1 2026:**
- DigitalOcean mendominasi tier CRITICAL (661 IP, 34,4%) - kampanye PostExploitation terkoordinasi
- 2 payload hash dominan mencakup 96% dari seluruh file downloads
- 9 malicious URL teridentifikasi dari 5 IP server C2
- Surge period 9–13 Maret: volume serangan naik +98% dari baseline
- Omegatech LTD sebagai ASN dengan aktivitas CredentialAccess terbesar (17,6% dari seluruh chains)

Detail lengkap: [`Q1 (March 2026)/BLOCKLIST_GUIDE.md`](Q1%20(March%202026)/BLOCKLIST_GUIDE.md)

### Q2 2026 - *Dijadwalkan: Juli 2026*

> Cakupan: April – Juni 2026. Blocklist akan dibandingkan dengan baseline Q1 untuk mengidentifikasi:
> - IP yang persisten lintas kuartal (persistent threat actors)
> - IP baru yang belum teridentifikasi sebelumnya (emerging threats)
> - Hash payload baru (payload rotation tracking)
> - Perubahan taktik atau infrastruktur attacker (threat evolution)

---

## File Formats and Usage

### File `.txt` - Import Langsung

File plain text berisi satu entry per baris tanpa header - dirancang untuk import langsung ke perangkat keamanan:

```
# Contoh: blocklist_ip_critical.txt
5.182.83.231
130.12.180.51
14.63.196.175
...
```

**Kompatibel dengan:** iptables, nftables, pfSense/OPNsense (URL Table Alias), fail2ban, Suricata IP reputation, Crowdsec, EDR watchlist, SIEM indicator feed.

### File `.csv` - Analisis dan Investigasi

File CSV menyertakan header dan metadata per entry:

```csv
ip,chains,events,country,asn,first_seen,last_seen
5.182.83.231,10,853,Spain,Avatel Telecom SA,2026-03-08 04:30 UTC,2026-03-21 19:07 UTC
```

**Kolom tersedia:** IP/Hash/URL, jumlah chains, total events, negara, ASN, first seen timestamp, last seen timestamp.

### File `_stats.json` - Automation

JSON mentah berisi seluruh statistik untuk scripted processing:

```python
import json
with open('_stats.json') as f:
    stats = json.load(f)

critical_count = stats['tier_counts']['CRITICAL']['unique']
# → 1922
```

---

## Integration Guide 

### Firewall (iptables/nftables)

```bash
# Block seluruh tier CRITICAL
while IFS= read -r ip; do
  iptables -A INPUT -s "$ip" -j DROP
done < "Q1 (March 2026)/blocklist_ip_critical.txt"
```

### SIEM (Elastic/Splunk/Wazuh)

```bash
# Upload sebagai threat intelligence indicator
# Elastic: Security → Threat Intelligence → Upload IOC
# Splunk: Enterprise Security → Threat Intel → Local File
# Wazuh: CDB lists → custom blocklist
```

### EDR (Hash blocking)

```bash
# Import SHA256 ke EDR blocklist
# CrowdStrike: IOC Management → Import
# SentinelOne: Threat Intelligence → Hash Blocklist
# Defender for Endpoint: Indicators → File hashes
cat "Q1 (March 2026)/blocklist_sha256.txt"
```

### Web Proxy / DNS Sinkhole

```bash
# Block C2 server IPs
cat "Q1 (March 2026)/blocklist_urls.txt"
# Ekstrak IP dari URL dan tambahkan ke sinkhole
```

---

## Operational Principles

### Time-To-Live (TTL)

IOC bersifat temporal - efektivitasnya menurun seiring waktu karena *threat actor* merotasi infrastruktur. Rekomendasi TTL per tier:

| Tier | TTL | Alasan |
|---|---|---|
| CRITICAL | 90 hari | Infrastruktur PostExploit cenderung persisten |
| HIGH | 60 hari | Exploitation tools dirotasi lebih cepat |
| MEDIUM | 30 hari | Brute-force bots sering berganti IP |
| LOW | 14 hari | Scanner turnover sangat tinggi |
| SHA256 | ∞ (permanen) | Hash tidak berubah kecuali recompile |
| URL | 30 hari | Hosting infrastructure bisa takedown/rotate |

### Cross-Quarter Analysis

Mulai Q2 2026, setiap release akan menyertakan analisis delta:

- **Persistent IPs:** IP yang muncul di ≥2 kuartal berturut-turut - indikator *advanced persistent threat*
- **New IPs:** IP yang baru muncul di kuartal terbaru - indikator *emerging threat*
- **Dropped IPs:** IP yang aktif di Q(n-1) tetapi tidak di Q(n) - kemungkinan dirotasi atau di-takedown
- **Hash evolution:** Tracking rotasi payload - apakah hash baru muncul menggantikan yang lama?
- **Infrastructure shift:** Perubahan ASN atau geographic distribution - apakah attacker memindahkan infrastruktur?

### False Positive Considerations

Data berasal dari honeypot - setiap interaksi *per definisi* tidak sah. Namun:

- **Tier LOW** mengandung legitimate security scanners (Censys, Shodan) - jangan block tanpa review
- **Cloud provider IPs** (DigitalOcean, AWS, Google) - block per-IP, bukan per-ASN range
- **Consumer ISP** IPs (MTN, Vodafone, Korea Telecom) - kemungkinan compromised devices; terapkan TTL ketat

---

## Kontributor dan Lisensi

| Aspek | Detail |
|---|---|
| **Analyst** | VulneraX Threat Intelligence Team |
| **Data source** | T-Pot CE Honeypot Sensor |
| **Classification** | TLP:AMBER |
| **Usage** | Internal Blue Team / SOC operational use |
| **Redistribusi** | Sesuai kebijakan TLP:AMBER - hanya kepada pihak yang membutuhkan |

---

## Referensi Umum

- MITRE ATT&CK Framework - https://attack.mitre.org/
- David Bianco, *The Pyramid of Pain* (2013) - IOC hierarchy
- FIRST TLP Protocol - https://www.first.org/tlp/
- T-Pot Honeypot - https://github.com/telekom-security/tpotce
- STIX/TAXII Standards - https://oasis-open.github.io/cti-documentation/

---

*Blocklist Repository - Established Q1 2026*  
*Maintained by VulneraX Threat Intelligence Team*

