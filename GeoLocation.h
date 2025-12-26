#pragma once

#include <Arduino.h>
#include <functional>
#include "esp_wifi.h"

#ifdef ESP8266
    #include <ESP8266WiFi.h>
    //#define ERROR_DEBUG
#elif defined(ESP32)
    #include <WiFi.h>
#endif

enum SetTime {
    NTP_ONLY,
    HTTP_TIME
};

namespace GeoLocation
{
    // Константы для размеров строковых полей
    static const size_t IP_SIZE = 16;
    static const size_t COUNTRY_SIZE = 32;
    static const size_t CITY_SIZE = 64;
    static const size_t TIMEZONE_SIZE = 48;
    static const time_t LIKE_VALID_TIME = 1609459200;
    static const long httpCorrectionMs = 900;

    inline void wifiTime(){
        int64_t tsf_time = esp_wifi_get_tsf_time(WIFI_IF_STA);
        Serial.printf("Current TSF time: %lld us\n", tsf_time);

        Serial.printf("Local time %lu\n", time(nullptr));
    }

    // Структура для хранения часового пояса
    struct TimeZone
    {
        char tz[TIMEZONE_SIZE] = "";
        int offset = 0;  // Смещение в секундах (UTC+offset)
        
        bool isValid() const { return tz[0] != '\0' || offset != 0; }
        
        void printTo(Print &p) const
        {
            p.printf("Timezone: %s\n", tz);
            p.printf("UTC Offset: %d sec (%+.1f hrs)\n", offset, offset / 3600.0);
        }
    };

    // Структура для хранения геоданных (только координаты и часовой пояс)
    struct GeoData
    {
        float latitude = 0.0;
        float longitude = 0.0;
        TimeZone timezone;
        
        bool isValid() const { return latitude != 0.0 || longitude != 0.0; }
        
        void printTo(Print &p) const
        {
            p.printf("Location: %.4f, %.4f\n", latitude, longitude);
            timezone.printTo(p);
        }
    };

    // Состояния асинхронного запроса
    enum class State
    {
        Idle,           // Ожидание
        Connecting,     // Подключение к серверу
        SendingRequest, // Отправка запроса
        Receiving,      // Получение ответа
        AllParsed,      // Парсинг данных
        SettingTime,    // Установка времени
        Completed,      // Успешное завершение
        Error           // Ошибка
    };
    const char * stateToStr(const State s);

    // Типы ошибок
    enum class RequestError
    {
        None,           // Нет ошибки
        NoConnection,   // Нет WiFi
        Timeout,        // Таймаут
        RateLimited,    // Превышен лимит запросов
        ParseError,     // Ошибка парсинга
        HttpError,      // Ошибка HTTP
        Unknown         // Неизвестная ошибка
    };
    const char* errorToStr(RequestError error);

    enum Line {
        Status,
        Country,
        City,
        Lat,
        Lon,
        TimeZoneLine,  // Переименовано, чтобы не конфликтовало с структурой
        Offset,
        MyIP,
        AllLine
    };

    enum ProgressPercents {
        None = 0,
        Connecting = 10,
        _oneLineParsed = (60 / Line::AllLine),
        RequestSended = 20,
        Receiving = 30,
        HeaderParsed = 40,
        AllParsed = HeaderParsed + (7 * _oneLineParsed),
        Completed = 100
    };

    // Колбэки для событий
    using ProgressCallback = std::function<void(State state, int progress)>;
    using CompleteCallback = std::function<void(const GeoData& data, RequestError error)>;

    class GeoLocation
    {
    public:
        GeoLocation();
        ~GeoLocation();
        
        /**
         * Начать асинхронное получение геолокации
         * @param data Указатель на структуру GeoData для сохранения координат и часового пояса
         * @param autoSetTime Автоматически установить системное время из заголовка HTTP
         * @param language Двухбуквенный код языка (ru, en и т.д.)
         * @param ip Указатель для сохранения IP-адреса (если nullptr - не сохранять)
         * @param country Указатель для сохранения страны (если nullptr - не сохранять)
         * @param city Указатель для сохранения города (если nullptr - не сохранять)
         * @return true если запрос начат успешно
         */
        bool begin(GeoData* data = nullptr, bool autoSetTime = ::NTP_ONLY, const char* language = nullptr,
                   char* ip = nullptr, char* country = nullptr, char* city = nullptr);

        /**
         * Получение геолокации (блокирующая)
         * @param data Указатель на структуру GeoData для сохранения координат и часового пояса
         * @param autoSetTime Автоматически установить системное время из заголовка HTTP
         * @param language Двухбуквенный код языка (ru, en и т.д.)
         * @param timeout таймаут в милисекундах
         * @param ip Указатель для сохранения IP-адреса (если nullptr - не сохранять)
         * @param country Указатель для сохранения страны (если nullptr - не сохранять)
         * @param city Указатель для сохранения города (если nullptr - не сохранять)
         * @return true если успешно получен ответ
         */
        bool getLocation(GeoData* data = nullptr, bool autoSetTime = ::NTP_ONLY, const char* language = nullptr,
                         unsigned long timeout = 10000,
                         char* ip = nullptr, char* country = nullptr, char* city = nullptr);

        /**
         * Остановить выполнение запроса
         */
        void stop();
        
        /**
         * Основной цикл обработки (вызывать в loop())
         */
        void process();
        
        /**
         * Проверить, выполняется ли запрос
         */
        bool isRunning() const { return _state != State::Idle && _state != State::Completed && _state != State::Error; }
        
        /**
         * Получить текущее состояние
         */
        State getState() const { return _state; }
        const char * getStateStr() const { return stateToStr(_state); }

        /**
         * Получить прогресс (0-100)
         */
        int getProgress() const { return _progress; }
        
        /**
         * Получить результат (только после завершения)
         */
        const GeoData& getResult() const { return _resultData; }
        
        /**
         * Получить ошибку (только после завершения с ошибкой)
         */
        RequestError getError() const { return _error; }
        const char* getErrorStr() const { return errorToStr(_error); };

        /**
         * Установить таймаут запроса
         */
        void setTimeout(unsigned long timeoutMs) { _timeout = timeoutMs; }
        
        /**
         * Установить колбэк прогресса
         */
        void onProgress(ProgressCallback callback) { _progressCallback = callback; }
        
        /**
         * Установить колбэк завершения
         */
        void onComplete(CompleteCallback callback) { _completeCallback = callback; }
        
        /**
         * Использовать время из HTTP-заголовков
         */
        void enableHttpTime(bool enable) { _useHttpTime = enable; }
        
        /**
         * Получить время выполнения последнего запроса
         */
        unsigned long getLastExecutionTime() const { return _executionTime; }
        
        /**
         * Получить текущую установленную TZ в ESP
         * @return строка часового пояса с учетом инвертированного знака
         */
        static String getConfiguredTimeZone();

        /**
         * Обёртка для configTime
         */
        void configTime(const char* s1 = "pool.ntp.org", const char* s2 = nullptr, const char* s3 = nullptr) {
            ::configTime(0, 0, s1, s2, s3);
        }

    private:
        // Состояние машины
        State _state;
        RequestError _error;
        int _progress;
        unsigned long _timeout;
        unsigned long _startTime;
        unsigned long _lastActivity;
        unsigned long _executionTime;
        bool _useHttpTime;
        bool _autoSetTime;
        String _language;
        long _currentOffset;
        
        // Данные
        GeoData _resultData;           // Для хранения результата (если не передан указатель)
        GeoData* _dataPtr;             // Указатель на внешнюю структуру GeoData
        
        // Указатели для дополнительных данных
        char* _ipPtr;
        char* _countryPtr;
        char* _cityPtr;
        
        // Временные буферы для парсинга
        char _tempIp[IP_SIZE] = "";
        char _tempCountry[COUNTRY_SIZE] = "";
        char _tempCity[CITY_SIZE] = "";
        TimeZone _tempTimezone;
        float _tempLatitude = 0.0;
        float _tempLongitude = 0.0;
        
        // HTTP-клиент и состояние
        WiFiClient _client;
        String _responseBuffer;
        int _linesReceived;
        String _currentLine;
        bool _headersParsed;
        bool _httpDateSet;

        // Колбэки
        ProgressCallback _progressCallback;
        CompleteCallback _completeCallback;
        
        // Приватные методы
        void setState(State newState);
        void setProgress(int progress);
        void setError(RequestError error);
        
        // Методы обработки
        bool connectToServer();
        void sendHttpRequest();
        void processResponse();
        bool parseResponseLine(const String& line, int lineIndex);
        time_t parseHttpDate(const String& httpDate) const;
        void setSystemTime(const time_t unixTime, const long usCorrections = 0);
        void _configTime();
        void completeRequest();
        void saveParsedData();
    };
}