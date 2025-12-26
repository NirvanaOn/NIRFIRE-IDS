# 🔥 NIRFIRE-IDS
### Passive ESP8266 Wireless Intrusion Detection System (IDS)

NIRFIRE-IDS is a **passive, embedded Wireless Intrusion Detection System** built on the **ESP8266** platform.  
It continuously monitors nearby Wi-Fi traffic in **promiscuous mode** to detect common wireless attack patterns — **without injecting, jamming, or disrupting any packets**.

This project is designed for **educational and defensive security research**, focusing on how wireless attacks can be detected at the 802.11 frame level.

---

## 🛡️ Key Features

- 📡 **Passive Wi-Fi Monitoring**
  - Promiscuous mode (sniffing only)
  - No packet injection or interference

- 🚨 **Attack Pattern Detection**
  - Deauthentication / Disassociation floods
  - Beacon flood attacks (global & per-BSSID)
  - Probe request floods
  - Evil Twin detection (same SSID, different BSSID)
  - Hidden SSID beacon abuse
  - Excessive MAC randomization detection

- 🔄 **Channel Control**
  - Automatic channel hopping (channels 1–13)
  - Manual single-channel lock via Serial commands

- 📊 **Window-Based Reporting**
  - Periodic statistics and alerts
  - Clear, readable console output

- 💡 **Embedded-Friendly Design**
  - Lightweight logic
  - Designed within ESP8266 memory constraints

---

## ⚙️ How It Works (High Level)

1. ESP8266 runs in **station + promiscuous mode**
2. Nearby 802.11 frames are **captured passively**
3. Frame subtypes are analyzed:
   - Deauthentication
   - Beacon frames
   - Probe requests
   - Other management frames
4. Counters are collected within a **time window**
5. Detection logic evaluates thresholds
6. Alerts are generated and counters reset

👉 No traffic is modified or transmitted at any stage.

---

## 🖥️ Serial Commands

**Baud Rate:** `115200`

| Command | Description |
|------|------------|
| `h` | Show help |
| `a` | Enable automatic channel hopping |
| `s <ch>` | Lock scanning to a single channel (1–13) |
| `q` | Show current channel mode |

---

## 📦 Requirements

- ESP8266 board (NodeMCU, ESP-12, etc.)
- Arduino IDE or PlatformIO
- ESP8266 Arduino Core
- USB-to-Serial connection

---

## ⚠️ Limitations

- Detection is **heuristic-based**, not signature-perfect
- Frame parsing is best-effort due to SDK constraints
- Not a replacement for enterprise-grade IDS solutions
- Intended for **learning, research, and monitoring**

---

## 📜 Disclaimer

> ⚠️ **Disclaimer**  
> This project is intended **only for educational and defensive security research purposes**.  
> It does **not perform attacks**, packet injection, or wireless interference.  
> The author is **not responsible for misuse** or deployment in unauthorized environments.

---

## 🙌 Author

**Nirvana (TheCyberNirvana)**  
Embedded Security | Wireless Defense | Cybersecurity Research

---

## ⭐ Final Note

If you are learning:
- Wireless security
- Embedded networking
- IDS concepts
- ESP8266 internals

👉 **NIRFIRE-IDS is built for you.**

---

## 🤖 Built with AI Assistance

This project was developed with the assistance of AI tools for:
- Code refinement and optimization  
- Logic validation and edge-case review  
- Documentation clarity and structure  

All architectural decisions, implementation logic, and final validation
were performed and verified by the author.
