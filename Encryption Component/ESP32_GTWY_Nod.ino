#include <WiFi.h>
#include <WiFiUdp.h>
#include <esp_now.h>
#include <ArduinoJson.h>

#include "mbedtls/gcm.h"
#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/base64.h"

const char* WIFI_SSID = "wifiName";
const char* WIFI_PASSWORD = "PW for wifi";

const char* PI_IP = "172.20.10.6";
const int PI_PORT = 5005;

WiFiUDP udp;

// 16-byte AES key for AES-128
uint8_t AES_KEY[16] = {
  0x10, 0x22, 0x33, 0x44,
  0x55, 0x66, 0x77, 0x88,
  0x99, 0xAA, 0xBB, 0xCC,
  0xDD, 0xEE, 0xF0, 0x12
};

// 32-byte HMAC-SHA256 key
uint8_t HMAC_KEY[32] = {
  0x91, 0x82, 0x73, 0x64,
  0x55, 0x46, 0x37, 0x28,
  0x19, 0x2A, 0x3B, 0x4C,
  0x5D, 0x6E, 0x7F, 0x80,
  0x11, 0x22, 0x33, 0x44,
  0x55, 0x66, 0x77, 0x88,
  0x99, 0xAA, 0xBB, 0xCC
};

int receivedCounter = 0;

// ================= BASE64 ENCODE =================

String base64Encode(const uint8_t* input, size_t inputLen) {
  size_t outputLen = 0;
  size_t bufferLen = inputLen * 2 + 20;

  unsigned char* output = (unsigned char*)malloc(bufferLen);

  if (!output) {
    return "";
  }

  int ret = mbedtls_base64_encode(
    output,
    bufferLen,
    &outputLen,
    input,
    inputLen
  );

  if (ret != 0) {
    free(output);
    return "";
  }

  String result = String((char*)output);
  free(output);

  return result;
}

// ================= RANDOM BYTES =================

void createRandomBytes(uint8_t* buffer, size_t len) {
  for (size_t i = 0; i < len; i++) {
    buffer[i] = random(0, 256);
  }
}

// ================= HMAC SHA256 =================

String calculateHMAC(String message) {
  uint8_t hmacResult[32];

  const mbedtls_md_info_t* mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  mbedtls_md_hmac(
    mdInfo,
    HMAC_KEY,
    sizeof(HMAC_KEY),
    (const unsigned char*)message.c_str(),
    message.length(),
    hmacResult
  );

  return base64Encode(hmacResult, 32);
}

// ================= SENSITIVITY CLASSIFICATION =================

String classifySensitivity(String payload) {
  bool hasPatientId = payload.indexOf("patient_id") >= 0;

  bool hasMedical =
    payload.indexOf("ecg") >= 0 ||
    payload.indexOf("spo2") >= 0 ||
    payload.indexOf("glucose") >= 0 ||
    payload.indexOf("temperature") >= 0;

  if (hasPatientId && hasMedical) {
    return "HIGH";
  }

  if (!hasPatientId && hasMedical) {
    return "MEDIUM";
  }

  return "LOW";
}

// ================= AES-GCM FOR HIGH SENSITIVITY =================

String encryptAESGCM(String plaintext, unsigned long& encryptTimeUs) {
  uint8_t nonce[12];
  uint8_t tag[16];

  createRandomBytes(nonce, sizeof(nonce));

  size_t plaintextLen = plaintext.length();
  uint8_t* ciphertext = (uint8_t*)malloc(plaintextLen);

  if (!ciphertext) {
    return "{}";
  }

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);

  unsigned long startTime = micros();

  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, AES_KEY, 128);

  int ret = mbedtls_gcm_crypt_and_tag(
    &gcm,
    MBEDTLS_GCM_ENCRYPT,
    plaintextLen,
    nonce,
    sizeof(nonce),
    NULL,
    0,
    (const unsigned char*)plaintext.c_str(),
    ciphertext,
    sizeof(tag),
    tag
  );

  encryptTimeUs = micros() - startTime;

  mbedtls_gcm_free(&gcm);

  if (ret != 0) {
    free(ciphertext);
    return "{}";
  }

  String ciphertextB64 = base64Encode(ciphertext, plaintextLen);
  String nonceB64 = base64Encode(nonce, sizeof(nonce));
  String tagB64 = base64Encode(tag, sizeof(tag));

  free(ciphertext);

  StaticJsonDocument<768> doc;
  doc["algorithm"] = "AES-GCM";
  doc["iv"] = nonceB64;
  doc["ciphertext"] = ciphertextB64;
  doc["tag"] = tagB64;

  String output;
  serializeJson(doc, output);

  return output;
}

// ================= AES-CTR + HMAC FOR MEDIUM SENSITIVITY =================

String encryptAESCTR_HMAC(String plaintext, unsigned long& encryptTimeUs) {
  uint8_t iv[16];
  createRandomBytes(iv, sizeof(iv));

  size_t plaintextLen = plaintext.length();
  uint8_t* ciphertext = (uint8_t*)malloc(plaintextLen);

  if (!ciphertext) {
    return "{}";
  }

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);

  uint8_t streamBlock[16];
  size_t ncOff = 0;
  memset(streamBlock, 0, sizeof(streamBlock));

  unsigned long startTime = micros();

  mbedtls_aes_setkey_enc(&aes, AES_KEY, 128);

  int ret = mbedtls_aes_crypt_ctr(
    &aes,
    plaintextLen,
    &ncOff,
    iv,
    streamBlock,
    (const unsigned char*)plaintext.c_str(),
    ciphertext
  );

  encryptTimeUs = micros() - startTime;

  mbedtls_aes_free(&aes);

  if (ret != 0) {
    free(ciphertext);
    return "{}";
  }

  String ciphertextB64 = base64Encode(ciphertext, plaintextLen);
  String ivB64 = base64Encode(iv, sizeof(iv));

  String hmacMessage = ivB64 + ciphertextB64;
  String hmacB64 = calculateHMAC(hmacMessage);

  free(ciphertext);

  StaticJsonDocument<768> doc;
  doc["algorithm"] = "AES-CTR-HMAC";
  doc["iv"] = ivB64;
  doc["ciphertext"] = ciphertextB64;
  doc["hmac"] = hmacB64;

  String output;
  serializeJson(doc, output);

  return output;
}

// ================= HMAC-ONLY FOR LOW SENSITIVITY =================

String protectLowSensitivity(String plaintext, unsigned long& encryptTimeUs) {
  unsigned long startTime = micros();

  String payloadB64 = base64Encode((const uint8_t*)plaintext.c_str(), plaintext.length());
  String hmacB64 = calculateHMAC(payloadB64);

  encryptTimeUs = micros() - startTime;

  StaticJsonDocument<768> doc;
  doc["algorithm"] = "HMAC-ONLY";
  doc["payload"] = payloadB64;
  doc["hmac"] = hmacB64;

  String output;
  serializeJson(doc, output);

  return output;
}

// ================= SEND FINAL PACKET TO RASPBERRY PI =================

void sendToRaspberryPi(String originalPayload) {
  receivedCounter++;

  unsigned long totalStart = micros();

  unsigned long classifyStart = micros();
  String sensitivity = classifySensitivity(originalPayload);
  unsigned long classifyTimeUs = micros() - classifyStart;

  unsigned long encryptTimeUs = 0;
  String encryptedPart;

  if (sensitivity == "HIGH") {
    encryptedPart = encryptAESGCM(originalPayload, encryptTimeUs);
  } 
  else if (sensitivity == "MEDIUM") {
    encryptedPart = encryptAESCTR_HMAC(originalPayload, encryptTimeUs);
  } 
  else {
    encryptedPart = protectLowSensitivity(originalPayload, encryptTimeUs);
  }

  StaticJsonDocument<1024> encDoc;
  DeserializationError error = deserializeJson(encDoc, encryptedPart);

  if (error) {
    Serial.println("Failed to parse encrypted JSON part");
    return;
  }

  unsigned long totalTimeUs = micros() - totalStart;

  StaticJsonDocument<1536> packet;

  packet["device_id"] = "ESP32_GATEWAY_ENCRYPTOR_01";
  packet["source_node"] = "ESP32_SENSOR_01";
  packet["seq"] = receivedCounter;
  packet["esp_timestamp"] = millis();
  packet["sensitivity"] = sensitivity;

  packet["algorithm"] = encDoc["algorithm"] | "";
  packet["iv"] = encDoc["iv"] | "";
  packet["ciphertext"] = encDoc["ciphertext"] | "";
  packet["tag"] = encDoc["tag"] | "";
  packet["hmac"] = encDoc["hmac"] | "";
  packet["payload"] = encDoc["payload"] | "";

  packet["classify_us"] = classifyTimeUs;
  packet["encrypt_us"] = encryptTimeUs;
  packet["total_us"] = totalTimeUs;
  packet["free_heap"] = ESP.getFreeHeap();
  packet["packet_size"] = originalPayload.length();

  String finalPacket;
  serializeJson(packet, finalPacket);

  udp.beginPacket(PI_IP, PI_PORT);
  udp.print(finalPacket);
  udp.endPacket();

  Serial.println();
  Serial.println("==================================================");
  Serial.println("DATA RECEIVED FROM ESP32-1");
  Serial.println("==================================================");
  Serial.println(originalPayload);

  Serial.println();
  Serial.println("==================================================");
  Serial.println("ADAPTIVE ENCRYPTION RESULT");
  Serial.println("==================================================");

  Serial.print("Sensitivity Level : ");
  Serial.println(sensitivity);

  Serial.print("Selected Algorithm: ");
  Serial.println((const char*)encDoc["algorithm"]);

  Serial.print("Classification Time us: ");
  Serial.println(classifyTimeUs);

  Serial.print("Encryption Time us    : ");
  Serial.println(encryptTimeUs);

  Serial.print("Total Processing us   : ");
  Serial.println(totalTimeUs);

  Serial.print("Free Heap             : ");
  Serial.println(ESP.getFreeHeap());

  Serial.println();
  Serial.println("Encrypted Packet Sent to Raspberry Pi:");
  Serial.println(finalPacket);
  Serial.println("==================================================");
}

// ================= ESP-NOW RECEIVE CALLBACK =================
// This version is correct for ESP32 board package 2.0.14

void onDataReceive(const uint8_t *mac_addr, const uint8_t *incomingData, int len) {
  char receivedData[350];
  memset(receivedData, 0, sizeof(receivedData));

  int copyLen = min(len, 349);
  memcpy(receivedData, incomingData, copyLen);

  String payload = String(receivedData);

  sendToRaspberryPi(payload);
}

// ================= SETUP =================

void setup() {
  Serial.begin(115200);
  delay(1000);

  randomSeed(esp_random());

  WiFi.mode(WIFI_AP_STA);

  Serial.println();
  Serial.println("==================================================");
  Serial.println("ESP32-2 Receiver + Adaptive Encryption Node");
  Serial.println("==================================================");

  Serial.print("ESP32-2 MAC Address: ");
  Serial.println(WiFi.macAddress());

  Serial.println();
  Serial.print("Connecting to Wi-Fi: ");
  Serial.println(WIFI_SSID);

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println();
  Serial.println("Wi-Fi Connected Successfully");

  Serial.print("ESP32-2 IP Address: ");
  Serial.println(WiFi.localIP());

  if (esp_now_init() != ESP_OK) {
    Serial.println("ESP-NOW initialization failed");
    return;
  }

  esp_now_register_recv_cb(onDataReceive);

  udp.begin(4210);

  Serial.println();
  Serial.println("ESP32-2 is ready.");
  Serial.println("Waiting for sensor data from ESP32-1...");
  Serial.println("==================================================");
}

// ================= LOOP =================

void loop() {
  delay(1000);
}