# CISA KEV for the 4.2-inch CrowPanel

This PlatformIO project targets the Elecrow ESP32-S3 CrowPanel with a 400x300 e-paper display. It shows the five most recent entries by date added, with CVE ID, vendor and product, and CISA's remediation due date. It checks CISA's GitHub mirror hourly over HTTPS and keeps the last successful results when an update fails.

## Wi-Fi setup

Join **CrowPanel-KEV** from a phone or computer using **kevdisplay**, then open **http://192.168.4.1** and select **Configure WiFi**. Select a 2.4 GHz network and enter its password there. If you need to change networks, hold **MENU** while restarting the CrowPanel. Press **MENU** during normal operation to refresh.

Turn the rotary switch to highlight one of the five KEVs. Press it to open the description, required action, and known ransomware use. Turn the switch to page through longer details. Press the switch again or use **EXIT** to return to the list.

## Build and upload

From this directory, run `pio run` to compile or `pio run -t upload --upload-port COM7` to build and flash. Update the COM port as needed. The default driver is for the V1.2A green-sticker variant. Holding **EXIT** during restart switches to the SSD1683 driver or back to the V1.2A driver.

[Elecrow hardware and examples](https://github.com/Elecrow-RD/CrowPanel-ESP32-4.2-E-paper-HMI-Display-with-400-300) | [CISA KEV data](https://github.com/cisagov/kev-data)
