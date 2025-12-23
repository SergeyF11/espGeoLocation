#include <Arduino.h>
#include "GeoLocation.h"

const char* ssid = "your_SSID";
const char* password = "your_PASSWORD";

GeoLocation::GeoLocation geoService;

// Колбэк прогресса
void onProgress(GeoLocation::State state, int progress)
{
    
    Serial.printf("[Progress] State: %s, Progress: %d%%\n", 
                GeoLocation::stateToStr(state), progress);
}

// Колбэк завершения
void onComplete(const GeoLocation::GeoData& data, GeoLocation::RequestError error)
{
    if (error == GeoLocation::RequestError::None)
    {
        Serial.println("\n=== Location Data ===");
        data.printTo(Serial);
        Serial.println("=====================");
        
        // Выводим текущее время
        time_t now = time(nullptr);
        struct tm* timeinfo = localtime(&now);
        Serial.printf("Current time: %02d:%02d:%02d\n",
                     timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
    }
    else
    {
        const char* errorNames[] = {
            "None", "NoConnection", "Timeout", "RateLimited",
            "ParseError", "HttpError", "Unknown"
        };
        
        Serial.printf("\n[Error] %s\n", errorNames[(int)error]);
    }
    
    Serial.printf("Execution time: %lu ms\n", geoService.getLastExecutionTime());
}

void setup()
{
    Serial.begin(115200);
    delay(1000);
    //configTime( 0 , 0, "pool.ntp.org", "time.nist.gov");

    Serial.println("=== Async GeoLocation Example ===\n");
    
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
    
    // Настраиваем сервис
    geoService.setTimeout(20000); // 20 секунд таймаут
    
    //geoService.enableHttpTime(true);
    geoService.onProgress(onProgress);
    geoService.onComplete(onComplete);
    geoService.configTime("pool.ntp.org", "time.nist.gov");

    // Запускаем запрос
    Serial.println("\nStarting async location request...");
    bool started = geoService.begin(true, "ru"); // Автоустановка времени, русский язык
    
    if (!started)
    {
        Serial.println("Failed to start request!");
    }
}

void loop()
{
    // Основной цикл обработки
    geoService.process();
    
    // Другая логика вашего приложения
    static unsigned long lastStatus = 0;
    if (millis() - lastStatus >= 1000)
    {
        lastStatus = millis();
        
        // Показываем статус
        if (geoService.isRunning())
        {
            Serial.printf("Running... State: %s, Progress: %d%%\n", 
                        geoService.getStateStr(), geoService.getProgress());
        }
        
        // Можно перезапустить запрос раз в минуту
        static unsigned long lastRequest = 0;
        if (millis() - lastRequest >= 60000 && !geoService.isRunning())
        {
            lastRequest = millis();
            Serial.println("\nRestarting location request...");
            geoService.begin(true, "ru");
        }
    }
    
    delay(10); // Небольшая задержка для стабильности
}