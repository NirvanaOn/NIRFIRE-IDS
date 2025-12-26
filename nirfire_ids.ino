/*************************************************
 * ESP8266 Wireless IDS — Extra Passive Detections
 * Adds: option for user to scan only a specific channel (via Serial)
 * Keeps original detection logic intact.
 *
 * Usage over Serial (115200):
 *  - h          : print help
 *  - a          : enable auto channel hopping (default)
 *  - s <ch>     : set single-channel scan to channel <ch> (1..13) and enable single-channel mode
 *  - q          : query current mode and selected channel
 *
 * Example:
 *  - Send "s 6" to lock scanning on channel 6.
 *  - Send "a" to resume automatic hopping.
 *************************************************/

#include <ESP8266WiFi.h>

extern "C" {
  #include "user_interface.h"
}

/* ============ SETTINGS ============ */
#define SERIAL_BAUD 115200
#define LED_PIN 2
#define LED_INVERT true

#define CH_TIME 140          // ms per channel
#define PKT_RATE 5           // Deauth packets threshold (original)
#define PKT_TIME 1           // Deauth time threshold (original)

#define BEACON_RATE_TH 80    // Beacon frames per window (original)

/* NEW thresholds */
#define PROBE_RATE_TH 120      // Probe requests per window -> probe flood
#define MAC_RAND_PERCENT_TH 60 // percent of locally-administered MACs to consider heavy MAC-randomization
#define PER_BSSID_BEACON_TH 60 // beacons per single BSSID in window
#define HIDDEN_SSID_TH 40      // hidden-SSID beacons threshold

#define MAX_APS 15
#define MAX_BEACON_STATS 30

const short channels[] = {1,2,3,4,5,6,7,8,9,10,11,12,13};

/* ============ STRUCT ============ */
struct AP {
  String ssid;
  uint8_t bssid[6];
};

AP aps[MAX_APS];
int apCount = 0;

/* ============ RUNTIME VARS ============ */
int ch_index = 0;
int deauth_rate = 0;
int beacon_rate = 0;
int attack_counter = 0;

unsigned long update_time = 0;
unsigned long ch_time = 0;

/* ============ NEW: extra counters & storage ============ */
int probe_rate = 0;              // probe requests count in window

// unique source mac pool (no per-MAC printouts, only used for stats)
#define MAX_MAC_POOL 120
uint8_t macPool[MAX_MAC_POOL][6];
int macPoolCount = 0;

// per-BSSID beacon counters (to detect single AP beacon flood)
struct BeaconStat {
  uint8_t bssid[6];
  uint16_t count;
  bool used;
};
BeaconStat beaconStats[MAX_BEACON_STATS];

// hidden SSID beacons count (SSID length==0)
int hidden_ssid_beacon_count = 0;

/* ============ USER CHANNEL MODE ============ */
/* false = auto hopping across channels[], true = single-channel mode */
bool singleChannelMode = false;
uint8_t selectedChannel = channels[0]; // actual channel number (1..13)

/* ============ UTILS ============ */
String macToStr(const uint8_t* m) {
  char buf[18];
  sprintf(buf,"%02X:%02X:%02X:%02X:%02X:%02X",
          m[0],m[1],m[2],m[3],m[4],m[5]);
  return String(buf);
}

static inline bool macEqual(const uint8_t* a, const uint8_t* b) {
  return memcmp(a,b,6) == 0;
}

static inline bool isLocallyAdministered(const uint8_t* mac) {
  // locally administered if bit 1 (0x02) is set in first octet
  return (mac[0] & 0x02) != 0;
}

/* add unique mac to pool (no duplicates) */
void addMacToPool(const uint8_t* src) {
  for (int i = 0; i < macPoolCount; i++)
    if (macEqual(macPool[i], src)) return;
  if (macPoolCount < MAX_MAC_POOL) {
    memcpy(macPool[macPoolCount++], src, 6);
  }
}

/* add/increment beacon stat for BSSID */
void addBeaconStat(const uint8_t* bssid) {
  for (int i = 0; i < MAX_BEACON_STATS; i++) {
    if (beaconStats[i].used && macEqual(beaconStats[i].bssid, bssid)) {
      beaconStats[i].count++;
      return;
    }
  }
  for (int i = 0; i < MAX_BEACON_STATS; i++) {
    if (!beaconStats[i].used) {
      beaconStats[i].used = true;
      memcpy(beaconStats[i].bssid, bssid, 6);
      beaconStats[i].count = 1;
      return;
    }
  }
  // if full, overwrite the smallest count to keep most active tracked
  int idx = 0;
  uint16_t minc = beaconStats[0].count;
  for (int i = 1; i < MAX_BEACON_STATS; i++) {
    if (beaconStats[i].count < minc) { minc = beaconStats[i].count; idx = i; }
  }
  memcpy(beaconStats[idx].bssid, bssid, 6);
  beaconStats[idx].count = 1;
  beaconStats[idx].used = true;
}

/* ============ SNIFFER ============ */
void ICACHE_RAM_ATTR sniffer(uint8_t* buf, uint16_t len) {
  if (!buf || len < 28) return;

  byte pkt_type = buf[12]; // frame subtype
  uint8_t* src = buf + 10;

  // Update unique MAC pool
  addMacToPool(src);

  // Deauth / Disassoc
  if (pkt_type == 0xA0 || pkt_type == 0xC0) {
    deauth_rate++;
    return;
  }

  // Probe request
  if (pkt_type == 0x40) {
    probe_rate++;
    return;
  }

  // Beacon frame
  if (pkt_type == 0x80) {
    beacon_rate++;

    // per-BSSID beacon stat
    addBeaconStat(src);

    // Try to detect hidden SSID: parse SSID tag best-effort
    // Tag parsing common start at offset 36 (best-effort across cores)
    if (len > 38) {
      uint8_t* tags = buf + 36;
      uint16_t tagsLen = len - 36;
      uint16_t idx = 0;
      while (idx + 2 <= tagsLen) {
        uint8_t tagNum = tags[idx];
        uint8_t tagLen = tags[idx+1];
        if (idx + 2 + tagLen > tagsLen) break;
        if (tagNum == 0) {
          // SSID tag
          if (tagLen == 0) hidden_ssid_beacon_count++;
          break;
        }
        idx += 2 + tagLen;
      }
    }

    return;
  }

  // other frames ignored
}

/* ============ ALERTS ============ */
void attack_started() {
  digitalWrite(LED_PIN, !LED_INVERT);
  Serial.println("🚨 DEAUTH ATTACK DETECTED");
}

void attack_stopped() {
  digitalWrite(LED_PIN, LED_INVERT);
  Serial.println("✅ Deauth attack stopped");
}

void beacon_flood_alert() {
  Serial.println("🚨 BEACON FLOOD DETECTED (global)");
}

void probe_flood_alert() {
  Serial.println("🚨 PROBE REQUEST FLOOD DETECTED");
}

void mac_rand_alert(int percent) {
  Serial.printf("⚠️  HIGH MAC RANDOMIZATION: %d%% locally-administered MACs\n", percent);
}

void per_bssid_beacon_alert(const uint8_t* bssid, int count) {
  Serial.printf("⚠️  BEACON FLOOD FROM AP %s count=%d\n", macToStr(bssid).c_str(), count);
}

void hidden_ssid_alert(int count) {
  Serial.printf("⚠️  MANY HIDDEN SSID BEACONS: %d\n", count);
}

/* ============ EVIL TWIN ============ */
void scanAPs() {
  wifi_promiscuous_enable(false);

  apCount = 0;
  int n = WiFi.scanNetworks();

  for (int i = 0; i < n && i < MAX_APS; i++) {
    aps[apCount].ssid = WiFi.SSID(i);
    memcpy(aps[apCount].bssid, WiFi.BSSID(i), 6);
    apCount++;
  }

  WiFi.scanDelete();
  wifi_promiscuous_enable(true);
}

bool evilTwinDetected() {
  for (int i = 0; i < apCount; i++) {
    for (int j = i + 1; j < apCount; j++) {
      if (aps[i].ssid == aps[j].ssid &&
          memcmp(aps[i].bssid, aps[j].bssid, 6) != 0) {

        Serial.println("🚨 EVIL TWIN DETECTED");
        Serial.println("SSID  : " + aps[i].ssid);
        Serial.println("BSSID1: " + macToStr(aps[i].bssid));
        Serial.println("BSSID2: " + macToStr(aps[j].bssid));
        Serial.println("------------------------");
        return true;
      }
    }
  }
  return false;
}

/* ============ SERIAL COMMANDS ============ */
void printHelp() {
  Serial.println(F("=== IDS SERIAL COMMANDS ==="));
  Serial.println(F("h          : help"));
  Serial.println(F("a          : auto channel hopping (default)"));
  Serial.println(F("s <ch>     : single-channel scan mode, set channel to <ch> (1..13)"));
  Serial.println(F("q          : query current mode"));
  Serial.println(F("==========================="));
}

void processSerialCommands() {
  // non-blocking input: read full line if available
  if (!Serial.available()) return;
  String line = Serial.readStringUntil('\n');
  line.trim();
  if (line.length() == 0) return;

  char cmd = line.charAt(0);
  if (cmd == 'h' || cmd == 'H') {
    printHelp();
    return;
  }
  if (cmd == 'a' || cmd == 'A') {
    singleChannelMode = false;
    Serial.println(F("[*] Auto channel hopping enabled"));
    return;
  }
  if (cmd == 's' || cmd == 'S') {
    // parse channel number after 's', e.g. "s 6" or "s6"
    String rest = line.substring(1);
    rest.trim();
    int ch = rest.toInt();
    if (ch >= 1 && ch <= 13) {
      selectedChannel = ch;
      singleChannelMode = true;
      wifi_set_channel(selectedChannel);
      Serial.printf("[*] Single-channel mode enabled: channel %d\n", selectedChannel);
    } else {
      Serial.println("[!] Invalid channel. Use 1..13. Example: s 6");
    }
    return;
  }
  if (cmd == 'q' || cmd == 'Q') {
    if (singleChannelMode) {
      Serial.printf("[*] Mode: SINGLE CHANNEL (ch %d)\n", selectedChannel);
    } else {
      Serial.println("[*] Mode: AUTO HOPPING");
    }
    return;
  }

  Serial.println("[!] Unknown command. Type 'h' for help.");
}

/* ============ SETUP ============ */
void setup() {
  Serial.begin(SERIAL_BAUD);
  delay(50);

  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LED_INVERT);

  WiFi.disconnect();
  wifi_set_opmode(STATION_MODE);

  wifi_set_promiscuous_rx_cb(sniffer);
  wifi_set_channel(channels[0]);
  wifi_promiscuous_enable(true);

  scanAPs();

  // init beaconStats
  for (int i = 0; i < MAX_BEACON_STATS; i++) { beaconStats[i].used = false; beaconStats[i].count = 0; }

  last_ch_time:
  ch_time = millis();
  update_time = millis();

  Serial.println("[+] ESP8266 Wireless IDS Started (extended)");
  printHelp();
}

/* ============ LOOP ============ */
void loop() {
  unsigned long now = millis();

  /* ================= DETECTION WINDOW ================= */
  if (now - update_time >= (sizeof(channels) * CH_TIME)) {
    update_time = now;

    Serial.println();
    Serial.println("====================================================");
    Serial.println("  NIRFIR ESP8266 WIRELESS IDS — WINDOW REPORT");
    Serial.println("====================================================");
    Serial.printf("  Uptime      : %lu sec\n", now / 1000);
    Serial.printf("  Channel Mode : %s\n", singleChannelMode ? "SINGLE" : "AUTO-HOP");
    Serial.printf("  Channel      : %d\n",
                  singleChannelMode ? selectedChannel : channels[ch_index]);
    Serial.println("----------------------------------------------------");

    /* ---------------- ALERT LOGIC ---------------- */

    bool anyAlert = false;

    // Deauth logic (Spacehuhn)
    if (deauth_rate >= PKT_RATE)
      attack_counter++;
    else {
      if (attack_counter >= PKT_TIME) attack_stopped();
      attack_counter = 0;
    }

    if (attack_counter == PKT_TIME) {
      attack_started();
      anyAlert = true;
    }

    // Beacon flood logic
    if (beacon_rate > BEACON_RATE_TH) {
      beacon_flood_alert();
      anyAlert = true;
    }

    // Probe flood
    if (probe_rate > PROBE_RATE_TH) {
      probe_flood_alert();
      anyAlert = true;
    }

    // MAC randomization ratio
    int randCount = 0;
    for (int i = 0; i < macPoolCount; i++)
      if (isLocallyAdministered(macPool[i])) randCount++;

    int randPercent = macPoolCount ? (randCount * 100 / macPoolCount) : 0;
    if (randPercent >= MAC_RAND_PERCENT_TH) {
      mac_rand_alert(randPercent);
      anyAlert = true;
    }

    // Per-BSSID beacon flood
    for (int i = 0; i < MAX_BEACON_STATS; i++) {
      if (!beaconStats[i].used) continue;
      if (beaconStats[i].count > PER_BSSID_BEACON_TH) {
        per_bssid_beacon_alert(beaconStats[i].bssid, beaconStats[i].count);
        anyAlert = true;
      }
    }

    // Hidden SSID beacon abuse
    if (hidden_ssid_beacon_count > HIDDEN_SSID_TH) {
      hidden_ssid_alert(hidden_ssid_beacon_count);
      anyAlert = true;
    }

    // Evil Twin scan (periodic)
    static unsigned long lastScan = 0;
    if (now - lastScan > 30000) {
      scanAPs();
      if (evilTwinDetected()) anyAlert = true;
      lastScan = now;
    }

    if (!anyAlert) {
      Serial.println("✅ STATUS: No active attack patterns detected");
    }

    /* ---------------- STATS TABLE ---------------- */

    Serial.println();
    Serial.println(" WINDOW STATISTICS ");
    Serial.println("----------------------------------------------------");
    Serial.printf("Deauth Frames      : %d\n", deauth_rate);
    Serial.printf("Beacon Frames      : %d\n", beacon_rate);
    Serial.printf("Probe Requests     : %d\n", probe_rate);
    Serial.printf("Unique MACs Seen   : %d\n", macPoolCount);
    Serial.printf("Hidden SSID Beacons: %d\n", hidden_ssid_beacon_count);
    Serial.println("----------------------------------------------------");
    Serial.println(" Window counters reset ");
    Serial.println("====================================================");

    /* ---------------- RESET WINDOW ---------------- */

    deauth_rate = 0;
    beacon_rate = 0;
    probe_rate = 0;
    macPoolCount = 0;
    hidden_ssid_beacon_count = 0;

    for (int i = 0; i < MAX_BEACON_STATS; i++) {
      beaconStats[i].used = false;
      beaconStats[i].count = 0;
    }
  }

  /* ================= CHANNEL HANDLING ================= */

  if (singleChannelMode) {
    static uint8_t lastSetChannel = 0;
    if (lastSetChannel != selectedChannel) {
      wifi_set_channel(selectedChannel);
      lastSetChannel = selectedChannel;
    }
  } else {
    if (now - ch_time >= CH_TIME) {
      ch_time = now;
      ch_index = (ch_index + 1) % (sizeof(channels)/sizeof(channels[0]));
      wifi_set_channel(channels[ch_index]);
    }
  }

  /* ================= SERIAL COMMANDS ================= */
  processSerialCommands();
}
