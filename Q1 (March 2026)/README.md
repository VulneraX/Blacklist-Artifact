# Panduan Blocklist Threat Intelligence - Q1 2026
## T-Pot Honeypot Attack Chain Analysis

> **Classification:** TLP:AMBER - Untuk penggunaan internal tim Threat Intelligence dan Blue Team  
> **Disiapkan oleh:** Mamanwhide 
> **Periode data:** 20 Februari 2026 00:00 UTC – 21 Maret 2026 23:59 UTC (30 hari)  
> **Tanggal pembuatan:** 22 Maret 2026  
> **Sumber data:** Elasticsearch index `attack-chain-*` dan `logstash-*` (T-Pot Honeypot Sensor)  
> **Versi:** 1.0  
> **Laporan induk:** `reports/2026_Q1_Initial_Report.md` (v1.3)

---

## 1. Pendahuluan

Dokumen ini merupakan panduan operasional (*Operational Threat Intelligence Guide*) yang disusun berdasarkan data empiris yang dikumpulkan melalui infrastruktur honeypot T-Pot selama 30 hari observasi pada kuartal pertama tahun 2026. Tujuan utamanya adalah menyediakan artefak *Indicators of Compromise* (IOC) yang telah dikurasi, diklasifikasikan, dan dideduplikasi - siap untuk diimplementasikan sebagai blocklist pada sistem pertahanan jaringan.

Dalam kerangka kerja *Cyber Threat Intelligence* (CTI), blocklist merepresentasikan bentuk **tactical intelligence** - yaitu intelijen teknis yang dapat langsung diterapkan pada perangkat keamanan (firewall, IDS/IPS, SIEM, EDR) untuk mendeteksi, memblokir, atau memantau aktivitas yang teridentifikasi sebagai *malicious*. Berbeda dengan *strategic intelligence* yang bersifat kontekstual dan jangka panjang, blocklist ini bersifat *actionable* dan *time-sensitive* - efektivitasnya menurun seiring waktu karena *threat actor* secara rutin merotasi infrastruktur serangan mereka.

### 1.1 Metodologi Pengumpulan Data

Data IOC diperoleh melalui proses bertingkat:

1. **Pengumpulan pasif (*Passive Collection*):** Infrastruktur honeypot T-Pot yang terdiri dari 13+ layanan emulasi (Cowrie SSH/Telnet, Dionaea SMB/HTTP, Mailoney SMTP, Ciscoasa VPN, dll.) mengumpulkan seluruh interaksi secara pasif. Tidak ada provokasi atau *active engagement* terhadap attacker.

2. **Korelasi otomatis (*Automated Correlation*):** Pipeline *Attack Chain* berjalan setiap jam, mengkorelasikan seluruh event dari satu IP dalam satu window waktu menjadi satu *attack chain record* dengan klasifikasi stage bertingkat.

3. **Klasifikasi severity:** Setiap chain memperoleh severity berdasarkan **stage tertinggi** yang dicapai - pemetaan 1:1 antara stage dan severity:

   | Stage | Severity | Deskripsi |
   |---|---|---|
   | 1-Reconnaissance | Low | Scanning, probing, banner grabbing |
   | 2-CredentialAccess | Medium | Brute-force, credential stuffing |
   | 3-Exploitation | High | Command execution awal, exploit delivery |
   | 4-PostExploitation | Critical | Payload download, persistence, privilege escalation |

4. **Deduplikasi lintas tier:** IP yang muncul di multiple tier dikategorikan berdasarkan **tier tertinggi saja**. IP dengan chain PostExploitation DAN CredentialAccess hanya dicatat di tier CRITICAL.

### 1.2 Statistik Keseluruhan

| Metrik | Nilai |
|---|---|
| **Total unique IP** (seluruh tier, deduplicated) | **14.550** |
| IP tier CRITICAL (PostExploitation) | **1.922** |
| IP tier HIGH (Exploitation) | **1.824** |
| IP tier MEDIUM (CredentialAccess) | **1.480** |
| IP tier LOW (Reconnaissance) | **9.324** |
| **SHA256 payload hashes** | **26** |
| **Malicious URLs** | **9** |
| Total attack chains (30 hari) | 45.822 |
| Total file download events | 6.552 |
| Unique downloader IPs | 1.859 |
| Periode observasi | 20 Feb – 21 Mar 2026 |

### 1.3 Struktur File dalam Folder Ini

```
Q1 (March 2026)/
├── BLOCKLIST_GUIDE.md                              ← Dokumen ini
├── _stats.json                                      ← Statistik mentah (JSON, untuk automation)
│
├── blocklist_ip_critical_postexploitation.csv       ← IP Critical - CSV dengan metadata
├── blocklist_ip_high_exploitation.csv               ← IP High - CSV dengan metadata
├── blocklist_ip_medium_credentialaccess.csv         ← IP Medium - CSV dengan metadata
├── blocklist_ip_low_reconnaissance.csv              ← IP Low - CSV dengan metadata
│
├── blocklist_ip_critical.txt                        ← IP Critical - 1 IP per baris (firewall import)
├── blocklist_ip_high.txt                            ← IP High - 1 IP per baris
├── blocklist_ip_medium.txt                          ← IP Medium - 1 IP per baris
├── blocklist_ip_low.txt                             ← IP Low - 1 IP per baris
├── blocklist_ip_all.txt                             ← SEMUA IP gabungan (14.550 entries)
│
├── blocklist_sha256.csv                             ← SHA256 hashes - CSV dengan metadata
├── blocklist_sha256.txt                             ← SHA256 hashes - 1 hash per baris
│
├── blocklist_urls.csv                               ← Malicious URLs - CSV dengan metadata
├── blocklist_urls.txt                               ← Malicious URLs - 1 URL per baris
│
├── file_downloads.csv                               ← Seluruh 6.552 file download events (CSV)
├── file_downloads_ips.txt                           ← 1.859 unique downloader IPs (plain text)
├── file_downloads_by_hash.csv                       ← Agregasi per SHA256 hash
└── file_downloads_by_ip.csv                         ← Agregasi per source IP
```

**Konvensi format:**
- **`.csv`** - Menyertakan header dan metadata (IP, chains, events, country, ASN, first/last seen). Digunakan untuk analisis, investigasi, dan enrichment.
- **`.txt`** - Satu entry per baris tanpa header. Digunakan untuk import langsung ke firewall rule, IDS/IPS signature, SIEM watchlist, atau automation script.

---

## 2. Tier CRITICAL - PostExploitation IPs (1.922 IP)

**File:** `blocklist_ip_critical_postexploitation.csv` | `blocklist_ip_critical.txt`  
**Rekomendasi:** [CRITICAL] **BLOCK IMMEDIATELY** pada perimeter firewall

### 2.1 Definisi dan Signifikansi

IP dalam tier ini telah **terkonfirmasi mencapai tahap PostExploitation** - stage tertinggi dalam kill chain yang dimonitor oleh sensor. Dalam konteks praktikal, *PostExploitation* berarti IP tersebut secara empiris terbukti telah:

- Berhasil melakukan autentikasi ke honeypot SSH (Cowrie) menggunakan credential yang valid
- Mengeksekusi perintah (*command execution*) pada sistem target setelah akses diperoleh
- Dalam banyak kasus: mengunduh payload malware, memodifikasi konfigurasi sistem, mengganti password root, atau membunuh proses kompetitor

Dalam terminologi MITRE ATT&CK, IP-IP ini telah mendemonstrasikan kapabilitas pada taktik **TA0002 (Execution)**, **TA0003 (Persistence)**, **TA0005 (Defense Evasion)**, dan **TA0040 (Impact)**. Tier ini merepresentasikan risiko tertinggi karena attacker telah melewati seluruh tahap kill chain dan secara aktif melakukan *post-compromise activity*.

### 2.2 Distribusi Geografis

**Top 10 negara asal (berdasarkan jumlah IP unik):**

| # | Negara | Jumlah IP | % dari Tier |
|---|---|---|---|
| 1 | United States | 222 | 11,6% |
| 2 | India | 158 | 8,2% |
| 3 | Indonesia | 131 | 6,8% |
| 4 | China | 130 | 6,8% |
| 5 | United Kingdom | 125 | 6,5% |
| 6 | Singapore | 119 | 6,2% |
| 7 | Hong Kong | 115 | 6,0% |
| 8 | Germany | 107 | 5,6% |
| 9 | Netherlands | 93 | 4,8% |
| 10 | Australia | 89 | 4,6% |

**Top 10 ASN (Autonomous System Number):**

| # | ASN / Organisasi | Jumlah IP | Tipe Infrastruktur |
|---|---|---|---|
| 1 | **DigitalOcean, LLC** | **661** | Cloud VPS |
| 2 | UCLOUD INFORMATION TECHNOLOGY HK | 89 | Cloud |
| 3 | PT Cloud Hosting Indonesia | 81 | Cloud VPS |
| 4 | Microsoft Corporation | 60 | Cloud (Azure) |
| 5 | Korea Telecom | 37 | ISP |
| 6 | OVH SAS | 33 | Cloud VPS |
| 7 | China Telecom Group | 30 | ISP |
| 8 | Chinanet | 26 | ISP |
| 9 | Byteplus Pte. Ltd. | 25 | Cloud |
| 10 | Cloud Host Pte Ltd | 20 | Cloud VPS |

> **Observasi kritis:** DigitalOcean mendominasi tier CRITICAL secara masif dengan **661 IP (34,4%)**. Temuan ini konsisten dengan analisis dalam laporan Q1 yang mengidentifikasi kampanye PostExploitation terkoordinasi yang menggunakan infrastruktur DigitalOcean secara sistematis. Namun, **blocking seluruh range IP DigitalOcean harus dipertimbangkan dengan sangat hati-hati** mengingat banyak layanan legitimate yang beroperasi pada provider yang sama. Pendekatan per-IP lebih sesuai dibanding per-ASN.

### 2.3 Top 20 IP Paling Aktif (CRITICAL)

| # | IP | Chains | Events | Negara | ASN | First Seen | Last Seen |
|---|---|---|---|---|---|---|---|
| 1 | `5.182.83.231` | 10 | 853 | Spain | Avatel Telecom, SA | 08 Mar | 21 Mar |
| 2 | `130.12.180.51` | 8 | 112 | USA | Omegatech LTD | 21 Feb | 14 Mar |
| 3 | `14.63.196.175` | 8 | 792 | South Korea | Korea Telecom | 08 Mar | 19 Mar |
| 4 | `213.209.159.158` | 8 | 219 | Taiwan | Feo Prest SRL | 20 Feb | 17 Mar |
| 5 | `102.88.137.80` | 7 | 483 | Nigeria | MTN Nigeria | 07 Mar | 18 Mar |
| 6 | `182.93.50.90` | 7 | 558 | Macao | CTM SARL | 11 Mar | 19 Mar |
| 7 | `102.88.137.213` | 6 | 852 | Nigeria | MTN Nigeria | 09 Mar | 19 Mar |
| 8 | `176.53.96.10` | 6 | 406 | Türkiye | Radore | 09 Mar | 19 Mar |
| 9 | `187.107.88.97` | 6 | 627 | Brazil | Claro NXT | 11 Mar | 20 Mar |
| 10 | `187.212.42.32` | 6 | 517 | Mexico | UNINET | 08 Mar | 12 Mar |
| 11 | `202.188.47.41` | 6 | 581 | Malaysia | TM Technology | 07 Mar | 15 Mar |
| 12 | `81.30.212.94` | 6 | 629 | Russia | JSC Ufanet | 07 Mar | 18 Mar |
| 13 | `103.183.74.4` | 5 | 782 | Indonesia | PT Cloud Hosting | 12 Mar | 20 Mar |
| 14 | `103.76.120.202` | 5 | 835 | Indonesia | PT Cloud Hosting | 08 Mar | 21 Mar |
| 15 | `154.125.147.88` | 5 | 956 | Senegal | SONATEL | 10 Mar | 21 Mar |
| 16 | `154.70.102.114` | 5 | 486 | Cameroon | MTN Cameroon | 07 Mar | 21 Mar |
| 17 | `20.173.116.24` | 5 | 335 | Qatar | Microsoft Corp. | 05 Mar | 14 Mar |
| 18 | `203.209.181.4` | 5 | 329 | Vietnam | Hanoi Telecom | 07 Mar | 21 Mar |
| 19 | `210.79.191.115` | 5 | 525 | Indonesia | PT Cloud Hosting | 05 Mar | 21 Mar |
| 20 | `43.156.71.43` | 5 | 345 | Singapore | Tencent | 08 Mar | 14 Mar |

### 2.4 Panduan Implementasi

```bash
# ── iptables (Linux) ──────────────────────────────────
while IFS= read -r ip; do
  iptables -A INPUT -s "$ip" -j DROP
done < blocklist_ip_critical.txt

# ── nftables (modern Linux) ───────────────────────────
nft add set inet filter blocklist_critical { type ipv4_addr \; }
while IFS= read -r ip; do
  nft add element inet filter blocklist_critical { "$ip" }
done < blocklist_ip_critical.txt
nft add rule inet filter input ip saddr @blocklist_critical drop

# ── pfSense / OPNsense ───────────────────────────────
# Upload blocklist_ip_critical.txt sebagai URL Table Alias
# Firewall → Aliases → Add → Type: URL Table (IPs)

# ── Suricata / Snort (IP reputation) ─────────────────
awk '{print $1",1"}' blocklist_ip_critical.txt > /etc/suricata/rules/critical_reputation.list

# ── fail2ban ──────────────────────────────────────────
while IFS= read -r ip; do
  fail2ban-client set sshd banip "$ip"
done < blocklist_ip_critical.txt
```

---

## 3. Tier HIGH - Exploitation IPs (1.824 IP)

**File:** `blocklist_ip_high_exploitation.csv` | `blocklist_ip_high.txt`  
**Rekomendasi:** [HIGH] **BLOCK** - prioritas tinggi setelah tier Critical

### 3.1 Definisi dan Signifikansi

IP dalam tier HIGH telah mencapai stage **3-Exploitation** - tahap di mana attacker mulai mengeksekusi perintah awal setelah melewati fase autentikasi. Meskipun belum mencapai PostExploitation secara penuh, IP-IP ini telah melampaui tahap *passive scanning* dan *credential guessing*, menunjukkan **kapabilitas dan niat eksploitasi aktif**.

Dalam kerangka *defense-in-depth*, tier HIGH merepresentasikan **pre-breach indicators** - IP yang mendemonstrasikan kemampuan untuk melakukan eksploitasi terhadap layanan yang terekspos. Blocking pada tier ini bersifat **preventif**: mencegah eskalasi dari Exploitation ke PostExploitation pada infrastruktur produksi.

### 3.2 Distribusi Geografis

| # | Negara | Jumlah IP | % dari Tier |
|---|---|---|---|
| 1 | United States | 716 | 39,3% |
| 2 | Germany | 133 | 7,3% |
| 3 | France | 110 | 6,0% |
| 4 | China | 108 | 5,9% |
| 5 | Singapore | 70 | 3,8% |

> **Catatan:** Dominasi USA (39,3%) terutama berasal dari cloud provider (DigitalOcean, Google Cloud, AWS, Azure) yang infrastrukturnya disalahgunakan untuk operasi scanning dan exploitation - bukan indikasi bahwa *threat actor* secara individual berasal dari negara tersebut.

---

## 4. Tier MEDIUM - CredentialAccess IPs (1.480 IP)

**File:** `blocklist_ip_medium_credentialaccess.csv` | `blocklist_ip_medium.txt`  
**Rekomendasi:** [MEDIUM] **RECOMMENDED BLOCK** - atau monitor dengan rate-limiting

### 4.1 Definisi dan Signifikansi

Tier MEDIUM mencakup IP yang secara aktif melakukan **credential brute-force** atau **credential stuffing** terhadap layanan autentikasi (SSH, VPN, SMTP, Redis). IP-IP ini mengirimkan kombinasi username/password secara berulang dalam durasi yang berkepanjangan - merupakan manifestasi konkret dari taktik MITRE **T1110 (Brute Force)**.

Dalam perspektif *risk assessment*, tier ini merepresentasikan ancaman aktif yang segera. Meskipun belum berhasil mengeksploitasi, volume serangan yang teramati (~17.698 CredentialAccess chains dalam 30 hari) menunjukkan bahwa probabilitas keberhasilan terhadap sistem dengan password lemah sangat tinggi secara statistik.

### 4.2 Distribusi Geografis

| # | Negara | Jumlah IP | % dari Tier |
|---|---|---|---|
| 1 | China | 262 | 17,7% |
| 2 | United States | 154 | 10,4% |
| 3 | Indonesia | 83 | 5,6% |
| 4 | Vietnam | 75 | 5,1% |
| 5 | Belgium | 66 | 4,5% |

### 4.3 Panduan Implementasi Terfokus

Tidak semua IP MEDIUM harus di-block secara absolut. Beberapa mungkin berasal dari ISP consumer atau researcher. Pendekatan bertingkat:

| Strategi | Kapan Digunakan | Implementasi |
|---|---|---|
| **Hard block** | Tidak ada hubungan bisnis dengan ASN sumber | `iptables -A INPUT -s IP -j DROP` |
| **Rate-limit** | IP dari provider yang juga digunakan legitimate | `iptables -A INPUT -s IP -m limit --limit 5/min -j ACCEPT` + `-j DROP` |
| **Monitor + alert** | Fallback minimum | SIEM watchlist dengan alert threshold |

---

## 5. Tier LOW - Reconnaissance IPs (9.324 IP)

**File:** `blocklist_ip_low_reconnaissance.csv` | `blocklist_ip_low.txt`  
**Rekomendasi:** [LOW] **MONITOR** - block opsional berdasarkan kebijakan organisasi

### 5.1 Definisi dan Signifikansi

Tier LOW adalah kategori terbesar (9.324 IP, 64% dari seluruh blocklist) yang mencakup IP yang hanya melakukan **reconnaissance**: port scanning, service enumeration, dan banner grabbing - tanpa melanjutkan ke tahap serangan aktif.

Penting untuk dipahami bahwa tier ini secara inheren heterogen:

- **Malicious scanner:** Bot yang memetakan internet untuk identifikasi target potensial
- **Legitimate security scanner:** Censys, Shodan, ONYPHE, BinaryEdge - platform riset keamanan
- **Worm residual:** Malware legacy (EternalBlue/WannaCry era) yang masih aktif scanning secara otonom
- **Researcher:** Akademisi dan analis keamanan yang melakukan internet-wide measurement

### 5.2 Distribusi Geografis

| # | Negara | Jumlah IP | % dari Tier |
|---|---|---|---|
| 1 | United States | 2.905 | 31,2% |
| 2 | China | 994 | 10,7% |
| 3 | India | 451 | 4,8% |
| 4 | Russia | 443 | 4,8% |
| 5 | United Kingdom | 389 | 4,2% |

### 5.3 Rekomendasi Penggunaan

> **Blocking seluruh tier LOW tidak direkomendasikan** kecuali organisasi menerapkan model *allowlist-only*. Pendekatan optimal:
>
> 1. Gunakan sebagai **SIEM enrichment feed** - bukan sebagai blocklist aktif
> 2. Korelasikan dengan log internal: deteksi IP yang pernah scan sensor DAN muncul di jaringan produksi
> 3. Prioritaskan blocking untuk IP LOW yang ASN-nya juga muncul di tier CRITICAL/HIGH (*cross-tier correlation*)

---

## 6. Blocklist SHA256 - Payload Hashes (26 Hash)

**File:** `blocklist_sha256.csv` | `blocklist_sha256.txt`  
**Rekomendasi:** [CRITICAL] **BLOCK IMMEDIATELY** pada EDR, email gateway, dan web proxy

### 6.1 Konteks Teoritis

SHA256 hashes dalam blocklist ini merepresentasikan **fingerprint kriptografis** dari file malicious yang diunduh oleh attacker setelah berhasil mengkompromikan sensor SSH (Cowrie). Dalam hierarchy IOC yang dirumuskan David Bianco (*Pyramid of Pain*, 2013), hash values berada di **dasar piramida** - sangat mudah bagi attacker untuk mengubahnya melalui recompilation atau repacking. Namun, selama hash belum dirotasi, detection berbasis hash menawarkan **zero false-positive rate** - setiap match adalah confirmed malicious.

### 6.2 Daftar Lengkap SHA256 Hashes

#### Tier 1 - Dominant Payloads (>100 downloads)

| # | SHA256 | Downloads | Unique IPs | First Seen | Last Seen | Klasifikasi |
|---|---|---|---|---|---|---|
| 1 | `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2` | **3.514** | **1.246** | 05 Mar | 22 Mar | DOMINANT - Cryptominer dropper |
| 2 | `1b20a210fe96e5a8abc347dfb91d7befecb4b5f9b7ed40d856410fac15952057` | **2.780** | **587** | 21 Feb | 21 Mar | DOMINANT - Versi awal/rotasi |
| 3 | `01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b` | **175** | **143** | 06 Mar | 21 Mar | SIGNIFICANT - Secondary dropper |

**Analisis:**
- Hash #1 dan #2 secara kolektif bertanggung jawab atas **96,1%** dari seluruh file download events (6.294 dari 6.552)
- Hash #2 (`1b20a210...`) aktif sejak **21 Februari** - lebih awal dari #1, mengindikasikan **payload rotation**: operator beralih dari satu dropper ke yang lain
- Kedua hash beroperasi paralel selama periode overlap (5–21 Maret), menunjukkan campaign infrastructure yang terorganisasi

#### Tier 2 - Minor Payloads (2–19 downloads)

| # | SHA256 | Downloads | IPs | Associated URL |
|---|---|---|---|---|
| 4 | `a5c41ad2a873e7904cb35754bf57108df0b72d5939ba9d9b0a8250affda6285d` | 19 | 5 | - |
| 5 | `bc54a596462c45edccac86fc9b77c5dbfaba914c86d5e35cabf4445ded3bb266` | 15 | 10 | - |
| 6 | `dccfd62d350184fc137b18acbdd56fceee07f2c7b7f89eb1071e7c4eb0f01bcd` | 8 | 2 | `http://103.56.149.224/cacti/oto` |
| 7 | `817fb161a8199e1cc57206461aca31154b2a69890ea7cef73ed7410c95671a87` | 7 | 1 | `http://172.94.9.106:8080/l.x86_64` |
| 8 | `32b44db3980a94e1be989a4c5605cb2b3ed2db6cfa208943c70ae2a82d983291` | 4 | 2 | `http://103.56.149.224/cacti/ns1.jpg` |
| 9 | `9701ae7249aa394624bf33096e3f5dd2be0bb778debba3364f5277a50874cc31` | 4 | 2 | `http://103.56.149.224/cacti/ns3.jpg` |
| 10 | `7ad5d373cc8ec9420f56476aa2d48ad45d67287db6cf6253c6ee868443279489` | 3 | 1 | `http://172.94.9.106:8080/l.x86_64` |
| 11 | `46de421734f272934e7f6b69db826d4f74db727e89d15a7884420bb625b6679f` | 2 | 1 | `http://185.91.127.182/1.sh` |
| 12 | `5221ec6e6edebc1a14023576bac25d830066695340c056405d9f0c172c5fa6b7` | 2 | 1 | `http://185.91.127.182/l.sh` |
| 13 | `ad955f2fc192c74bbab93a06edd77a4691fe3cd95d255f94664f5ac87674c283` | 2 | 2 | - |
| 14 | `1d45712bba2b79753dd55a98e55db0978e327ac01e27a99341ad9b2c264c4448` | 2 | 1 | - |
| 15 | `8a2fb1b1ee281817a2fd2d8e510db83a9ab2ed29e27ba248008ce1e165fc7479` | 2 | 1 | - |
| 16 | `8b3c537c5954161d21f26bbe3c3723f67b7e922692c91d870b3b9ca16dce74d2` | 2 | 1 | - |
| 17 | `efa54ea92b19f480b25a0c87c11324a0c8c3121a1d97ca411118e8383c60f8ab` | 2 | 1 | - |

#### Tier 3 - One-Shot Payloads (1 download)

| # | SHA256 | Associated URL |
|---|---|---|
| 18 | `0c889251c703623c3397893515aae9624f45c609fcf5881ace4b2e0a1857a88f` | - |
| 19 | `2a229b637f23b1f389d5bb15927bcf32a883d680c4d5fa490ddff279e674b8a6` | `http://130.12.180.124/8x6h0a.sh` |
| 20 | `4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865` | - |
| 21 | `47104de870ccfd602e40790f65569708d3f2256317e0cffe9ea4d86ac58281c5` | - |
| 22 | `47c2e12d095d77a8d7b471efa568af06a4ef90de34d700fd13b26aa768a8fe88` | - |
| 23 | `6b23334daf6181235f574ac71257918a1cb46295dfbb0a130babda29f3fdb08a` | `ftp://anonymous:anonymous@185.91.127.182/2.sh` |
| 24 | `78fd5eb896dfb151a3975bfdfdd7a6e924d52aab8756ee959b8102c2d1cca53f` | `http://176.65.139.34/xd/Space.mips` |
| 25 | `b1b8308d882329d9d10fed76e51cbdcba10a899abeeda81cda4764f61a4804d1` | - |
| 26 | `f74113ff44e07f9b366e89c2938a6db6f0a2f4b9c422de161f2f4bbff59ccd18` | - |

### 6.3 Panduan Implementasi

```yaml
# ── YARA Rule ─────────────────────────────────────────
rule TPot_Q1_2026_Dominant_Payloads {
    meta:
        description = "Dominant cryptominer droppers dari T-Pot Q1 2026"
        source      = "T-Pot Honeypot Sensor"
        tlp         = "AMBER"
        date        = "2026-03-22"
        severity    = "CRITICAL"
    condition:
        hash.sha256(0, filesize) == "a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2" or
        hash.sha256(0, filesize) == "1b20a210fe96e5a8abc347dfb91d7befecb4b5f9b7ed40d856410fac15952057" or
        hash.sha256(0, filesize) == "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"
}
```

```bash
# ── Filesystem scan ───────────────────────────────────
while IFS= read -r hash; do
  find / -type f -exec sha256sum {} + 2>/dev/null | grep -i "$hash"
done < blocklist_sha256.txt

# ── VirusTotal enrichment ─────────────────────────────
# https://www.virustotal.com/gui/file/<SHA256>
```

---

## 7. Blocklist URL - Malicious Download URLs (9 URL)

**File:** `blocklist_urls.csv` | `blocklist_urls.txt`  
**Rekomendasi:** [CRITICAL] **BLOCK IMMEDIATELY** pada web proxy, DNS sinkhole, dan firewall L7

### 7.1 Konteks Teoritis

URL dalam blocklist ini merupakan **payload delivery endpoints** - lokasi hosting file malicious yang diakses oleh attacker post-compromise. Setiap URL telah terverifikasi melalui Cowrie session logs: attacker melakukan SSH login → mengeksekusi `wget` atau `curl` → mendownload file dari URL ini. Dengan kata lain, URL-URL ini bukan hasil crawling atau inference - melainkan **confirmed C2/staging infrastructure**.

### 7.2 Daftar Lengkap URL

| # | URL | Downloads | Unique IPs | First Seen | Last Seen | Associated Hash |
|---|---|---|---|---|---|---|
| 1 | `http://172.94.9.106:8080/l.x86_64` | **10** | 1 | 27 Feb | 27 Feb | `817fb161...`, `7ad5d373...` |
| 2 | `http://103.56.149.224/cacti/oto` | **8** | 2 | 06 Mar | 21 Mar | `dccfd62d...` |
| 3 | `http://103.56.149.224/cacti/ns1.jpg` | **4** | 2 | 06 Mar | 21 Mar | `32b44db3...` |
| 4 | `http://103.56.149.224/cacti/ns3.jpg` | **4** | 2 | 06 Mar | 21 Mar | `9701ae72...` |
| 5 | `http://185.91.127.182/1.sh` | **2** | 1 | 24 Feb | 24 Feb | `46de4217...` |
| 6 | `http://185.91.127.182/l.sh` | **2** | 1 | 24 Feb | 24 Feb | `5221ec6e...` |
| 7 | `ftp://anonymous:anonymous@185.91.127.182/2.sh` | **1** | 1 | 24 Feb | 24 Feb | `6b23334d...` |
| 8 | `http://130.12.180.124/8x6h0a.sh` | **1** | 1 | 28 Feb | 28 Feb | `2a229b63...` |
| 9 | `http://176.65.139.34/xd/Space.mips` | **1** | 1 | 19 Mar | 19 Mar | `78fd5eb8...` |

### 7.3 Analisis Infrastruktur C2

Dari 9 URL teridentifikasi, terdapat **5 IP server C2/hosting** yang berfungsi sebagai infrastruktur distribusi malware:

| IP Server | Jumlah URL | Total Downloads | Tipe | Analisis |
|---|---|---|---|---|
| **103.56.149.224** | 3 | 16 | HTTP | Multi-file hosting dalam path `/cacti/` - masquerade sebagai Cacti monitoring tool |
| **172.94.9.106** | 1 | 10 | HTTP:8080 | ELF binary hosting pada non-standard port - Linux x86_64 dropper |
| **185.91.127.182** | 3 | 5 | HTTP + FTP | Dual-protocol infrastructure - shell script droppers via HTTP dan FTP anonymous |
| **130.12.180.124** | 1 | 1 | HTTP | Omegatech IP range (130.12.x.x) - terkait kampanye Incident #5 di laporan Q1 |
| **176.65.139.34** | 1 | 1 | HTTP | MIPS binary (`Space.mips`) - IoT/router targeting malware |

> **Rekomendasi tambahan:** Selain blocking URL spesifik, **block seluruh 5 IP server C2** pada level network firewall. Server-server ini merupakan infrastruktur aktif hosting dan distribusi malware.

### 7.4 Panduan Implementasi

```bash
# ── DNS Sinkhole (Pi-hole / AdGuard / Unbound) ───────
# Block C2 server IPs:
for ip in 172.94.9.106 103.56.149.224 185.91.127.182 130.12.180.124 176.65.139.34; do
  echo "$ip" >> /etc/pihole/custom.list
done

# ── Squid proxy ───────────────────────────────────────
acl blocklist_urls url_regex -i "/path/to/blocklist_urls.txt"
http_access deny blocklist_urls

# ── Suricata URL detection ────────────────────────────
alert http any any -> any any (msg:"T-Pot IOC: C2 server 103.56.149.224";
  content:"103.56.149.224"; http_host; sid:2026001; rev:1;)
alert http any any -> any any (msg:"T-Pot IOC: C2 server 172.94.9.106";
  content:"172.94.9.106"; http_host; sid:2026002; rev:1;)
```

---

## 8. File Downloads - Detail Lengkap (6.552 Events)

**File:** `file_downloads.csv` | `file_downloads_ips.txt` | `file_downloads_by_hash.csv` | `file_downloads_by_ip.csv`

### 8.1 Ringkasan

Data file download merepresentasikan aktivitas **post-compromise payload retrieval** yang terekam oleh Cowrie SSH honeypot. Setiap record mencatat satu event di mana attacker, setelah berhasil login via SSH, mengunduh file ke dalam sistem target - baik melalui perintah `wget`/`curl` maupun melalui mekanisme SCP/SFTP.

| Metrik | Nilai |
|---|---|
| **Total download events** | **6.552** |
| **Unique downloader IPs** | **1.859** |
| **Unique SHA256 hashes** | **26** |
| **Unique URLs** | **9** |
| **Unique destination files** | **829** |
| **Periode** | 21 Feb 2026 – 22 Mar 2026 |

### 8.2 Distribusi Download per Hash (Top 5)

| # | SHA256 (truncated) | Downloads | Unique IPs | % Total |
|---|---|---|---|---|
| 1 | `a8460f446be54041...` | 3.514 | 1.246 | 53,6% |
| 2 | `1b20a210fe96e5a8...` | 2.780 | 587 | 42,4% |
| 3 | `01ba4719c80b6fe9...` | 175 | 143 | 2,7% |
| 4 | `a5c41ad2a873e790...` | 19 | 5 | 0,3% |
| 5 | `bc54a596462c45ed...` | 15 | 10 | 0,2% |

Hash #1 (`a8460f44...`) merupakan SSH authorized_keys injector - menginjeksi kunci publik attacker ke ratusan path `~/.ssh/authorized_keys` pada berbagai user account untuk memastikan persistent access. Hash #2 (`1b20a210...`) merupakan versi sebelumnya atau rotasi payload dari kampanye yang sama, aktif sejak hari pertama observasi.

### 8.3 Top 10 Downloader IPs

| # | IP | Downloads | Unique Hashes | First Seen | Last Seen |
|---|---|---|---|---|---|
| 1 | `47.85.188.8` | 28 | 1 | 02 Mar | 02 Mar |
| 2 | `170.64.216.136` | 25 | 1 | 01 Mar | 02 Mar |
| 3 | `188.166.119.32` | 25 | 1 | 02 Mar | 02 Mar |
| 4 | `152.42.176.100` | 24 | 1 | 22 Feb | 22 Feb |
| 5 | `137.184.225.115` | 23 | 1 | 22 Feb | 22 Feb |
| 6 | `147.182.137.52` | 23 | 1 | 07 Mar | 07 Mar |
| 7 | `128.199.211.125` | 22 | 1 | 22 Feb | 22 Feb |
| 8 | `165.22.98.14` | 22 | 1 | 22 Feb | 22 Feb |
| 9 | `178.128.227.55` | 22 | 1 | 28 Feb | 28 Feb |
| 10 | `174.138.29.112` | 21 | 1 | 22 Feb | 22 Feb |

Pola yang teramati: sebagian besar top downloader IP melakukan seluruh download dalam sesi tunggal (first_seen = last_seen), mengindikasikan **automated campaign** di mana bot login, menjalankan payload injection ke semua user account yang terdeteksi, lalu disconnect.

### 8.4 Destination File Analysis

Dari 829 unique destination file paths, mayoritas absolut (>95%) merupakan path `~/.ssh/authorized_keys` pada berbagai user accounts - konfirmasi bahwa kampanye dominan bertujuan untuk **SSH key injection** sebagai mekanisme persistence. Beberapa destination files notable lainnya:

| Destination File | Signifikansi |
|---|---|
| `/dev/null` | Payload diunduh tanpa disimpan - kemungkinan testing atau decoy |
| `/root/.ssh/authorized_keys` | Root-level persistence |
| `/etc/hosts.deny` | Modifikasi access control - defense evasion |
| `/tmp/monaco` | Temporary staging - secondary payload |

### 8.5 Deskripsi File Output

| File | Isi | Format | Penggunaan |
|---|---|---|---|
| `file_downloads.csv` | Seluruh 6.552 events: timestamp, src_ip, shasum, url, destfile, session | CSV + header | Analisis forensik lengkap |
| `file_downloads_ips.txt` | 1.859 unique downloader IPs, sorted | 1 IP/baris | Import ke firewall, SIEM watchlist |
| `file_downloads_by_hash.csv` | 26 hash: download count, unique IPs, URLs, destfiles, first/last seen | CSV + header | Hash-centric threat analysis |
| `file_downloads_by_ip.csv` | 1.859 IP: download count, unique hashes, first/last seen | CSV + header | IP-centric threat analysis |

### 8.6 Panduan Penggunaan

```bash
# Block semua IP yang pernah melakukan file download (high-confidence malicious)
while IFS= read -r ip; do
  iptables -A INPUT -s "$ip" -j DROP
done < file_downloads_ips.txt

# Korelasi dengan log internal: cari IP downloader di access log
comm -12 <(sort file_downloads_ips.txt) <(sort /var/log/auth_ips.txt)

# Analisis hash yang paling banyak didownload
head -5 file_downloads_by_hash.csv | column -t -s,

# Cari IP dengan multiple hash downloads (sophisticated attacker)
awk -F, '$3 > 1' file_downloads_by_ip.csv
```

---

## 9. Strategi Implementasi dan Prioritas

### 9.1 Matriks Prioritas Deployment

| Prioritas | Aksi | Cakupan | Target Implementasi |
|---|---|---|---|
| **P0** | Block IP CRITICAL + SHA256 + URLs | Firewall + EDR + Proxy | **Segera** |
| **P1** | Block IP HIGH | Firewall perimeter | Dalam 24 jam |
| **P2** | Block/rate-limit IP MEDIUM | Firewall + fail2ban | Dalam 72 jam |
| **P3** | Monitor IP LOW | SIEM enrichment feed | Dalam 1 minggu |
| **P4** | Setup automated feed refresh | SIEM integration | Dalam 2 minggu |

### 9.2 Pertimbangan False Positive

Blocklist ini diturunkan dari data honeypot - setiap IP yang berinteraksi dengan sensor *per definisi* melakukan aktivitas tidak sah (sensor tidak menjalankan layanan legitimate). Namun, terdapat nuansa penting:

1. **Security scanners legitimate** (Censys, Shodan, ONYPHE, BinaryEdge) - terletak di tier LOW. Jangan block jika organisasi mengkonsumsi data mapping mereka.

2. **Cloud provider ranges** (DigitalOcean, AWS, Google, Azure) - muncul dominan di tier CRITICAL dan HIGH. Blocking **per-IP** (bukan per-ASN range) menghindari disruption layanan legitimate.

3. **ISP consumer** (MTN Nigeria, Korea Telecom, Vodafone) - IP dari ISP ini kemungkinan besar merupakan perangkat terkompromi. Implementasikan dengan **TTL** (*Time-To-Live*) dan lakukan review berkala.

### 9.3 Jadwal Maintenance

| Aspek | Frekuensi | Aksi |
|---|---|---|
| Refresh blocklist | Setiap 30 hari | Regenerasi dari data T-Pot terbaru |
| TTL review (CRITICAL) | 90 hari | Validasi apakah IP masih aktif |
| TTL review (HIGH) | 60 hari | Validasi apakah IP masih aktif |
| TTL review (MEDIUM) | 30 hari | Validasi atau pruning |
| TTL review (LOW) | 14 hari | Refresh atau discard |
| Hash validation | Setiap 14 hari | Cek VirusTotal; rotasi terdeteksi? |

---

## 10. Referensi

| Sumber | Relevansi |
|---|---|
| MITRE ATT&CK Framework - https://attack.mitre.org/ | Taxonomy taktik dan teknik serangan |
| David Bianco, *The Pyramid of Pain* (2013) | IOC hierarchy dan efektivitas detection |
| FIRST TLP Protocol - https://www.first.org/tlp/ | Klasifikasi distribusi informasi |
| T-Pot Honeypot - https://github.com/telekom-security/tpotce | Platform sensor sumber data |
| Laporan Q1 2026 v1.4 - `reports/2026_Q1_Initial_Report.md` | Analisis lengkap threat landscape |

---

*Panduan Blocklist Threat Intelligence - Q1 2026 (v1.0)*  
*Sumber: T-Pot Attack Chain Analysis System*  
*Stack: Elasticsearch 9.2.3 | Index: attack-chain-\*, logstash-\* | Pipeline: Attack Chain Hourly Aggregate*  
*Generated: 22 Maret 2026*