#include <Arduino.h>
#include <ArduinoJson.h>
#include <GxEPD2_BW.h>
#include <HTTPClient.h>
#include <Preferences.h>
#include <WiFiClientSecure.h>
#include <WiFiManager.h>
#include <time.h>

#include "root_certificate.h"

namespace {
constexpr int menuPin = 2;
constexpr int exitPin = 1;
constexpr int width = 400;
constexpr int height = 300;
constexpr size_t rows = 5;
constexpr uint32_t refreshMs = 60UL * 60 * 1000;
constexpr uint32_t retryMs = 5UL * 60 * 1000;
constexpr char catalogUrl[] =
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json";

GxEPD2_BW<GxEPD2_420_GDEY042T81, height> ssd(GxEPD2_420_GDEY042T81(45, 46, 47, 48));
GxEPD2_BW<GxEPD2_420_SE0420NQ04, height> uc(GxEPD2_420_SE0420NQ04(45, 46, 47, 48));
Preferences settings;
bool alternatePanel;
uint32_t nextRefresh;

struct Entry {
  char id[24];
  char product[100];
  char added[11];
  char due[11];
};

struct Snapshot {
  Entry entries[rows];
  uint32_t count;
};

Snapshot current{};
bool showingError;
bool dashboardDrawn;

int nextToken(Stream& stream) {
  char byte;
  do {
    if (stream.readBytes(&byte, 1) != 1) return -1;
  } while (isspace(static_cast<unsigned char>(byte)));
  return static_cast<unsigned char>(byte);
}

bool fetchCatalog(Snapshot& snapshot) {
  if (WiFi.status() != WL_CONNECTED) return false;

  struct tm utc;
  if (!getLocalTime(&utc, 10000)) {
    Serial.println("Waiting for NTP clock");
    return false;
  }

  WiFiClientSecure client;
  client.setCACert(rootCertificate);
  HTTPClient http;
  // HTTP/1.0 provides a plain response stream without chunk framing.
  http.useHTTP10(true);
  http.setTimeout(12000);
  if (!http.begin(client, catalogUrl)) return false;
  int status = http.GET();
  if (status != HTTP_CODE_OK) {
    Serial.printf("KEV HTTP status %d\n", status);
    return false;
  }

  Stream& stream = http.getStream();
  stream.setTimeout(12000);
  if (!stream.find("\"vulnerabilities\"") || nextToken(stream) != ':' ||
      nextToken(stream) != '[') return false;

  JsonDocument filter;
  for (const char* key : {"cveID", "vendorProject", "product", "dateAdded", "dueDate"}) {
    filter[key] = true;
  }

  for (;;) {
    JsonDocument record;
    auto error = deserializeJson(record, stream, DeserializationOption::Filter(filter));
    if (error) {
      Serial.printf("KEV JSON error %s\n", error.c_str());
      return false;
    }
    Entry entry{};
    const char* id = record["cveID"] | "";
    const char* added = record["dateAdded"] | "";
    const char* due = record["dueDate"] | "";
    if (strncmp(id, "CVE-", 4) || strlen(added) != 10 || strlen(due) != 10) return false;
    strlcpy(entry.id, id, sizeof(entry.id));
    strlcpy(entry.added, added, sizeof(entry.added));
    strlcpy(entry.due, due, sizeof(entry.due));
    snprintf(entry.product, sizeof(entry.product), "%s / %s",
             record["vendorProject"] | "", record["product"] | "");

    ++snapshot.count;
    for (auto& row : snapshot.entries) {
      const int dateOrder = strcmp(entry.added, row.added);
      if (dateOrder > 0 || (dateOrder == 0 && strcmp(entry.id, row.id) > 0)) {
        std::swap(entry, row);
      }
      if (!entry.id[0]) break;
    }

    const int separator = nextToken(stream);
    if (separator == ']') return nextToken(stream) == '}' && snapshot.count > 0;
    if (separator != ',') return false;
  }
}

void textAt(Adafruit_GFX& canvas, int x, int y, int size, const char* text) {
  canvas.setCursor(x, y);
  canvas.setTextSize(size);
  canvas.print(text);
}

template<class Panel>
void draw(Panel& display, const char* status, bool wifiSetup) {
  display.init(115200, true, 10, false);
  display.setRotation(0);
  display.setFullWindow();
  display.setTextWrap(false);
  display.firstPage();
  do {
    display.fillScreen(GxEPD_WHITE);
    display.fillRect(0, 0, width, 44, GxEPD_BLACK);
    display.setTextColor(GxEPD_WHITE);
    textAt(display, 12, 10, 3, "CISA KEV");
    display.setTextColor(GxEPD_BLACK);

    if (wifiSetup) {
      textAt(display, 12, 70, 2, "Connect to Wi-Fi");
      textAt(display, 12, 108, 2, "Network: CrowPanel-KEV");
      textAt(display, 12, 135, 2, "Password: kevdisplay");
      textAt(display, 12, 173, 2, "Open 192.168.4.1");
    } else {
      for (size_t i = 0; i < rows && current.entries[i].id[0]; ++i) {
        const auto& entry = current.entries[i];
        const int y = 50 + i * 45;
        textAt(display, 12, y, 2, entry.id);
        char product[63];
        snprintf(product, sizeof(product), "%.62s", entry.product);
        if (strlen(entry.product) >= sizeof(product)) strcpy(product + 59, "...");
        for (char* ch = product; *ch; ++ch) {
          if (static_cast<unsigned char>(*ch) > 126) *ch = '?';
        }
        textAt(display, 12, y + 17, 1, product);
        char dates[50];
        snprintf(dates, sizeof(dates), "Added %s     Due %s", entry.added, entry.due);
        textAt(display, 12, y + 28, 1, dates);
        display.drawFastHLine(12, y + 40, 376, GxEPD_BLACK);
      }
    }
    textAt(display, 12, 282, 1, status);
  } while (display.nextPage());
  display.hibernate();
}

void show(const char* status, bool wifiSetup = false) {
  if (alternatePanel) draw(uc, status, wifiSetup);
  else draw(ssd, status, wifiSetup);
}

void refresh() {
  Snapshot candidate{};
  if (fetchCatalog(candidate)) {
    const bool changed = memcmp(&current, &candidate, sizeof(candidate)) != 0;
    if (changed) {
      current = candidate;
      settings.putBytes("catalog", &current, sizeof(current));
    }
    if (changed || showingError || !dashboardDrawn) {
      char status[64];
      snprintf(status, sizeof(status), "%lu catalog entries | MENU refresh",
               static_cast<unsigned long>(current.count));
      show(status);
    }
    showingError = false;
    nextRefresh = millis() + refreshMs;
    Serial.printf("Fetched %lu KEV entries\n", static_cast<unsigned long>(current.count));
  } else {
    if (!showingError || !dashboardDrawn) show("Update failed | Retrying in 5 min");
    showingError = true;
    nextRefresh = millis() + retryMs;
  }
  dashboardDrawn = true;

}
}  // namespace

void setup() {
  Serial.begin(115200);
  pinMode(menuPin, INPUT_PULLUP);
  pinMode(exitPin, INPUT_PULLUP);
  pinMode(7, OUTPUT);
  digitalWrite(7, HIGH);
  pinMode(41, OUTPUT);
  digitalWrite(41, HIGH);
  SPI.begin(12, -1, 11, 45);
  ssd.epd2.selectSPI(SPI, SPISettings(4000000, MSBFIRST, SPI_MODE0));
  uc.epd2.selectSPI(SPI, SPISettings(4000000, MSBFIRST, SPI_MODE0));

  settings.begin("kev", false);
  alternatePanel = settings.getBool("alternate", true);
  if (digitalRead(exitPin) == LOW) {
    alternatePanel = !alternatePanel;
    settings.putBool("alternate", alternatePanel);
  }
  Serial.printf("Panel: %s\n", alternatePanel ? "UC8276C" : "SSD1683");
  if (settings.getBytesLength("catalog") == sizeof(current)) {
    settings.getBytes("catalog", &current, sizeof(current));
  }

  WiFi.mode(WIFI_STA);
  WiFiManager wifi;
  wifi.setConnectTimeout(20);
  wifi.setConfigPortalTimeout(180);
  wifi.setAPCallback([](WiFiManager*) {
    show("Select Configure WiFi in the setup page", true);
    Serial.println("Wi-Fi setup: CrowPanel-KEV / kevdisplay at 192.168.4.1");
  });
  if (digitalRead(menuPin) == LOW) wifi.startConfigPortal("CrowPanel-KEV", "kevdisplay");
  else wifi.autoConnect("CrowPanel-KEV", "kevdisplay");
  WiFi.setAutoReconnect(true);
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  showingError = true;  // Force the first successful refresh to draw.

  refresh();
}

void loop() {
  static bool wasPressed = false;
  const bool pressed = digitalRead(menuPin) == LOW;
  if ((pressed && !wasPressed) || static_cast<int32_t>(millis() - nextRefresh) >= 0) {
    refresh();
  }
  wasPressed = pressed;
  delay(30);
}
