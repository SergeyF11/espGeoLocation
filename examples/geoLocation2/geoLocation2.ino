#include <Arduino.h>
#include "GeoLocation.h"

const char* ssid = "your_SSID";
const char* password = "your_PASSWORD";

void printTime(time_t now = time(nullptr)){
    // Выводим текущее время
    
    struct tm* timeinfo = localtime(&now);
    Serial.printf("Current time: %02d:%02d:%02d\n",
                     timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
}


void setup()
{
    Serial.begin(115200);
    delay(1000);
    //configTime( 0 , 0, "pool.ntp.org", "time.nist.gov");

    Serial.println("=== Blocking GeoLocation Example ===\n");
    
    // Подключаемся к WiFi
    //WiFi.begin(ssid, password);
    WiFi.begin();
    
    Serial.print("Connecting to WiFi");
    while (WiFi.status() != WL_CONNECTED)
    {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\nConnected!");
    
    GeoLocation::wifiTime();

    GeoLocation::GeoLocation geoLoc;
    geoLoc.configTime("pool.ntp.org", "time.nist.gov");
    
    GeoLocation::GeoData geoData;
    char ip[16], country[32], city[64];
    geoLoc.getLocation(&geoData, true, "ru", 10000, ip, country, city);

    // Запускаем запрос
    Serial.println("\nStarting location request...");
    //bool started = geoService.begin(true, "ru"); // Автоустановка времени, русский язык
    bool res = geoLoc.getLocation(&geoData, true, "ru", 10000, ip, country, city); //geoService.getLocation(true, "ru");
    
    if (res) {
        Serial.println("\n=== Location Data ===");
        geoLoc.getResult().printTo(Serial);
        Serial.println("=====================");
        

    } else 
    {
        Serial.println("Failed to start request!");
    }

    GeoLocation::wifiTime();
}

void loop() {
    printTime();
   delay(10000);
}