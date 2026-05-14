#include <WiFi.h>
#include <esp_now.h>
#include <ArduinoJson.h>

uint8_t receiverMac[] = {0xD4, 0xE9, 0xF4, 0x71, 0x78, 0x2C};

int packetCounter = 1;

void onDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
  Serial.print("ESP-NOW Send Status: ");
  Serial.println(status == ESP_NOW_SEND_SUCCESS ? "SUCCESS" : "FAILED");
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  WiFi.mode(WIFI_STA);

  Serial.println("ESP32-1 Sensor Node Started");
  Serial.print("ESP32-1 MAC Address: ");
  Serial.println(WiFi.macAddress());

  if (esp_now_init() != ESP_OK) {
    Serial.println("ESP-NOW init failed");
    return;
  }

  esp_now_register_send_cb(onDataSent);

  esp_now_peer_info_t peerInfo = {};
  memcpy(peerInfo.peer_addr, receiverMac, 6);
  peerInfo.channel = 0;
  peerInfo.encrypt = false;

  if (esp_now_add_peer(&peerInfo) != ESP_OK) {
    Serial.println("Failed to add ESP32-2 peer");
    return;
  }

  Serial.println("ESP32-1 Ready to send sensor data...");
}

String generateSensorPayload() {
  StaticJsonDocument<256> doc;

  int mode = packetCounter % 3;

  doc["device_id"] = "ESP32_SENSOR_01";
  doc["seq"] = packetCounter;
  doc["timestamp"] = millis();

  if (mode == 0) {
    // HIGH sensitivity: patient ID + medical values
    doc["patient_id"] = "PID1001";
    doc["ecg"] = random(70, 120);
    doc["spo2"] = random(94, 100);
    doc["glucose"] = random(80, 150);
    doc["temperature"] = random(360, 380) / 10.0;
  } 
  else if (mode == 1) {
    // MEDIUM sensitivity: medical values only
    doc["ecg"] = random(70, 120);
    doc["spo2"] = random(94, 100);
    doc["glucose"] = random(80, 150);
    doc["temperature"] = random(360, 380) / 10.0;
  } 
  else {
    // LOW sensitivity: device status only
    doc["battery"] = random(70, 100);
    doc["signal"] = random(-70, -35);
    doc["firmware"] = "v1.0.0";
    doc["status"] = "normal";
  }

  String output;
  serializeJson(doc, output);
  return output;
}

void loop() {
  String payload = generateSensorPayload();

  Serial.println();
  Serial.println("Generated Sensor Payload:");
  Serial.println(payload);

  esp_err_t result = esp_now_send(receiverMac, (uint8_t *)payload.c_str(), payload.length() + 1);

  if (result == ESP_OK) {
    Serial.println("Payload sent to ESP32-2");
  } else {
    Serial.println("Error sending payload");
  }

  packetCounter++;
  delay(3000);
}