#include <Arduino.h>
#include <ArduinoJson.h>
#include <GxEPD2_BW.h>
#include <HTTPClient.h>
#include <Preferences.h>
#include <WiFiClientSecure.h>
#include <WiFiManager.h>
#include <time.h>
#include <memory>

#include "root_certificate.h"

namespace {
constexpr int menuPin = 2;
constexpr int exitPin = 1;
constexpr int previousPin = 6;
constexpr int nextPin = 4;
constexpr int selectPin = 5;
constexpr int width = 400;
constexpr int height = 300;
constexpr size_t rows = 5;
constexpr int firstRowY = 50;
constexpr int rowHeight = 45;
constexpr int markerWidth = 16;
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

struct Details {
  char description[1024];
  char action[640];
  char ransomware[12];
};

struct CatalogSummary {
  Entry entries[rows];
  uint32_t count;
};

struct Snapshot {
  CatalogSummary summary;
  Details details[rows];
};

Snapshot current{};
size_t selected;
size_t drawnSelection;
bool detailOpen;
size_t detailPage;
size_t detailPageCount = 1;
bool redrawPending;
uint32_t redrawAt;

struct Button {
  explicit Button(int inputPin) : pin(inputPin) {}
  int pin;
  bool sampled = false;
  bool stable = false;
  uint32_t changedAt = 0;

  bool pressed() {
    const bool low = digitalRead(pin) == LOW;
    if (low != sampled) {
      sampled = low;
      changedAt = millis();
    }
    if (stable == sampled || millis() - changedAt < 15) return false;
    stable = sampled;
    return stable;
  }
};
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
  for (const char* key : {"cveID", "vendorProject", "product", "dateAdded", "dueDate",
                          "shortDescription", "requiredAction", "knownRansomwareCampaignUse"}) {
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

    ++snapshot.summary.count;
    auto& entries = snapshot.summary.entries;
    for (size_t i = 0; i < rows; ++i) {
      const int dateOrder = strcmp(entry.added, entries[i].added);
      if (dateOrder < 0 || (dateOrder == 0 && strcmp(entry.id, entries[i].id) <= 0)) continue;

      for (size_t j = rows - 1; j > i; --j) {
        entries[j] = entries[j - 1];
        snapshot.details[j] = snapshot.details[j - 1];
      }
      entries[i] = entry;
      auto& details = snapshot.details[i];
      details = {};
      strlcpy(details.description, record["shortDescription"] | "", sizeof(details.description));
      strlcpy(details.action, record["requiredAction"] | "", sizeof(details.action));
      strlcpy(details.ransomware, record["knownRansomwareCampaignUse"] | "", sizeof(details.ransomware));
      break;
    }

    const int separator = nextToken(stream);
    if (separator == ']') return nextToken(stream) == '}' && snapshot.summary.count > 0;
    if (separator != ',') return false;
  }
}

void textAt(Adafruit_GFX& canvas, int x, int y, int size, const char* text) {
  canvas.setCursor(x, y);
  canvas.setTextSize(size);
  canvas.print(text);
}

size_t visibleEntries() {
  return min(static_cast<size_t>(current.summary.count), rows);
}

String displayText(const char* text) {
  String result;
  for (const auto* byte = reinterpret_cast<const unsigned char*>(text); *byte; ++byte) {
    if (*byte >= 32 && *byte <= 126) result += static_cast<char>(*byte);
    else if (isspace(*byte)) result += ' ';
    else if ((*byte & 0xC0) != 0x80) result += '?';
  }
  return result;
}

void drawDetails(Adafruit_GFX& display) {
  const auto& entry = current.summary.entries[selected];
  const auto& details = current.details[selected];
  char dates[64];
  snprintf(dates, sizeof(dates), "Added %s     CISA due %s", entry.added, entry.due);
  textAt(display, 12, 54, 1, dates);

  String body = displayText(entry.product);
  body += "\n\nDescription\n";
  body += details.description[0] ? displayText(details.description) : String("Awaiting a catalog update.");
  body += "\n\nRequired action\n";
  body += details.action[0] ? displayText(details.action) : String("Awaiting a catalog update.");
  body += "\n\nKnown ransomware use: ";
  body += details.ransomware[0] ? details.ransomware : "Unavailable";

  constexpr size_t columns = 62;
  constexpr size_t linesPerPage = 18;
  size_t line = 0;
  size_t start = 0;
  while (start < body.length()) {
    size_t end = start;
    size_t space = start;
    while (end < body.length() && body[end] != '\n' && end - start < columns) {
      if (body[end] == ' ') space = end;
      ++end;
    }
    if (end < body.length() && body[end] != ' ' && body[end] != '\n' && space > start) {
      end = space;
    }
    if (line / linesPerPage == detailPage) {
      textAt(display, 12, 74 + (line % linesPerPage) * 11, 1, body.substring(start, end).c_str());
    }
    ++line;
    start = end;
    while (start < body.length() && body[start] == ' ') ++start;
    if (start < body.length() && body[start] == '\n') ++start;
  }
  detailPageCount = max(size_t{1}, (line + linesPerPage - 1) / linesPerPage);
}

void drawSelectionMarker(Adafruit_GFX& display) {
  const int y = firstRowY + selected * rowHeight;
  display.fillTriangle(4, y + 2, 4, y + 14, 11, y + 8, GxEPD_BLACK);
}

template<class Panel>
void draw(Panel& display, const char* status, bool wifiSetup) {
  display.setRotation(0);
  display.setFullWindow();
  display.setTextWrap(false);
  display.firstPage();
  do {
    display.fillScreen(GxEPD_WHITE);
    display.fillRect(0, 0, width, 44, GxEPD_BLACK);
    display.setTextColor(GxEPD_WHITE);
    textAt(display, 12, 10, detailOpen && !wifiSetup ? 2 : 3,
           detailOpen && !wifiSetup ? current.summary.entries[selected].id : "CISA KEV");
    display.setTextColor(GxEPD_BLACK);

    if (wifiSetup) {
      textAt(display, 12, 70, 2, "Connect to Wi-Fi");
      textAt(display, 12, 108, 2, "Network: CrowPanel-KEV");
      textAt(display, 12, 135, 2, "Password: kevdisplay");
      textAt(display, 12, 173, 2, "Open 192.168.4.1");
    } else if (detailOpen) {
      drawDetails(display);
      char page[64];
      snprintf(page, sizeof(page), "Page %u/%u | Turn to scroll | Press or EXIT to go back",
               static_cast<unsigned>(detailPage + 1), static_cast<unsigned>(detailPageCount));
      textAt(display, 12, 268, 1, page);
    } else {
      for (size_t i = 0; i < visibleEntries(); ++i) {
        const auto& entry = current.summary.entries[i];
        const int y = firstRowY + i * rowHeight;
        textAt(display, markerWidth, y, 2, entry.id);
        String product = displayText(entry.product);
        if (product.length() > 62) product = product.substring(0, 59) + "...";
        textAt(display, markerWidth, y + 17, 1, product.c_str());
        char dates[50];
        snprintf(dates, sizeof(dates), "Added %s     Due %s", entry.added, entry.due);
        textAt(display, markerWidth, y + 28, 1, dates);
        display.drawFastHLine(markerWidth, y + 40, 372, GxEPD_BLACK);
      }
      if (visibleEntries()) drawSelectionMarker(display);
    }
    textAt(display, 12, 282, 1, status);
  } while (display.nextPage());
}

template<class Panel>
void moveSelectionMarker(Panel& display) {
  const int top = firstRowY + min(selected, drawnSelection) * rowHeight;
  const int bottom = firstRowY + max(selected, drawnSelection) * rowHeight + 15;
  display.setPartialWindow(0, top, markerWidth, bottom - top);
  display.firstPage();
  do {
    display.fillScreen(GxEPD_WHITE);
    drawSelectionMarker(display);
  } while (display.nextPage());
  // Keep controller RAM available for the next partial update.
  display.powerOff();
}

void show(const char* status, bool wifiSetup = false) {
  if (alternatePanel) draw(uc, status, wifiSetup);
  else draw(ssd, status, wifiSetup);
}

void showCatalog() {
  char status[64];
  if (showingError) {
    snprintf(status, sizeof(status), "Update failed | MENU retries");
  } else {
    snprintf(status, sizeof(status), "Turn to select | Press for details | MENU refresh");
  }
  show(status);
  drawnSelection = selected;
  dashboardDrawn = true;
  redrawPending = false;
}

bool saveCatalog() {
  JsonDocument cache;
  cache["count"] = current.summary.count;
  JsonArray entries = cache["entries"].to<JsonArray>();
  for (size_t i = 0; i < visibleEntries(); ++i) {
    const auto& entry = current.summary.entries[i];
    const auto& details = current.details[i];
    JsonArray row = entries.add<JsonArray>();
    row.add(entry.id);
    row.add(entry.product);
    row.add(entry.added);
    row.add(entry.due);
    row.add(details.description);
    row.add(details.action);
    row.add(details.ransomware);
  }
  String data;
  serializeJson(cache, data);
  return settings.putBytes("catalog-v2", data.c_str(), data.length() + 1) == data.length() + 1;
}

void loadCatalog() {
  if (settings.isKey("catalog-v2")) {
    JsonDocument cache;
    const size_t length = settings.getBytesLength("catalog-v2");
    std::unique_ptr<char[]> data(new (std::nothrow) char[length]);
    if (length && data && settings.getBytes("catalog-v2", data.get(), length) == length &&
        !deserializeJson(cache, data.get(), length)) {
      const auto entries = cache["entries"].as<JsonArray>();
      const uint32_t count = cache["count"] | 0U;
      if (entries.size() == min(static_cast<size_t>(count), rows)) {
        current.summary.count = count;
        for (size_t i = 0; i < visibleEntries(); ++i) {
          auto& entry = current.summary.entries[i];
          auto& details = current.details[i];
          const JsonArrayConst row = entries[i].as<JsonArrayConst>();
          strlcpy(entry.id, row[0] | "", sizeof(entry.id));
          strlcpy(entry.product, row[1] | "", sizeof(entry.product));
          strlcpy(entry.added, row[2] | "", sizeof(entry.added));
          strlcpy(entry.due, row[3] | "", sizeof(entry.due));
          strlcpy(details.description, row[4] | "", sizeof(details.description));
          strlcpy(details.action, row[5] | "", sizeof(details.action));
          strlcpy(details.ransomware, row[6] | "", sizeof(details.ransomware));
        }
        return;
      }
    }
  }
  if (settings.isKey("catalog") && settings.getBytesLength("catalog") == sizeof(current.summary)) {
    settings.getBytes("catalog", &current.summary, sizeof(current.summary));
  }
}

void refresh() {
  // Keep the staging buffer off the Arduino loop task's stack.
  static Snapshot candidate;
  memset(&candidate, 0, sizeof(candidate));
  if (fetchCatalog(candidate)) {
    const bool changed = memcmp(&current, &candidate, sizeof(candidate)) != 0;
    const bool wasShowingError = showingError;
    showingError = false;
    if (changed) {
      char selectedId[sizeof(Entry::id)];
      strlcpy(selectedId, current.summary.entries[selected].id, sizeof(selectedId));
      current = candidate;
      if (saveCatalog()) {
        if (settings.isKey("catalog")) settings.remove("catalog");
      } else {
        Serial.println("Could not save KEV cache");
      }
      size_t index = 0;
      while (index < visibleEntries() && strcmp(selectedId, current.summary.entries[index].id)) ++index;
      if (index < visibleEntries()) {
        selected = index;
      } else {
        selected = 0;
        detailOpen = false;
      }
      detailPage = 0;
    }
    if (changed || wasShowingError || !dashboardDrawn) showCatalog();
    nextRefresh = millis() + refreshMs;
    Serial.printf("Fetched %lu KEV entries\n", static_cast<unsigned long>(current.summary.count));
  } else {
    const bool needsDraw = !showingError || !dashboardDrawn;
    showingError = true;
    if (needsDraw) showCatalog();
    nextRefresh = millis() + retryMs;
  }
}
}  // namespace

void setup() {
  Serial.begin(115200);
  pinMode(menuPin, INPUT_PULLUP);
  pinMode(exitPin, INPUT_PULLUP);
  pinMode(previousPin, INPUT_PULLUP);
  pinMode(nextPin, INPUT_PULLUP);
  pinMode(selectPin, INPUT_PULLUP);
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
  if (alternatePanel) uc.init(115200, true, 10, false);
  else ssd.init(115200, true, 10, false);
  Serial.printf("Panel: %s\n", alternatePanel ? "UC8276C" : "SSD1683");
  loadCatalog();

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

  refresh();
}

void loop() {
  static Button menu{menuPin}, back{exitPin}, previous{previousPin}, next{nextPin}, select{selectPin};
  const bool refreshPressed = menu.pressed();
  const bool backPressed = back.pressed();
  const bool selectPressed = select.pressed();
  const int step = static_cast<int>(next.pressed()) - static_cast<int>(previous.pressed());
  const int count = visibleEntries();

  if (count > 0) {
    if (selectPressed || (backPressed && detailOpen)) {
      detailOpen = !detailOpen;
      detailPage = 0;
      showCatalog();
    } else if (step != 0) {
      if (detailOpen) {
        const size_t page = constrain(static_cast<int>(detailPage) + step, 0,
                                      static_cast<int>(detailPageCount) - 1);
        if (page != detailPage) {
          detailPage = page;
          redrawPending = true;
        }
      } else {
        selected = (static_cast<int>(selected) + step + count) % count;
        redrawPending = selected != drawnSelection;
      }
      redrawAt = millis() + 100;
    }
  }

  if (refreshPressed || static_cast<int32_t>(millis() - nextRefresh) >= 0) refresh();
  if (redrawPending && static_cast<int32_t>(millis() - redrawAt) >= 0) {
    if (detailOpen || !dashboardDrawn) {
      showCatalog();
    } else {
      if (alternatePanel) moveSelectionMarker(uc);
      else moveSelectionMarker(ssd);
      drawnSelection = selected;
      redrawPending = false;
    }
  }
  delay(5);
}
