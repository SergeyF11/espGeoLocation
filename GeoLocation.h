#pragma once

#include <Arduino.h>
#include <functional>

#ifdef ESP8266
    #include <ESP8266WiFi.h>

    //#define ERROR_DEBUG

#elif defined(ESP32)
    #include <WiFi.h>
#endif

enum SetTime{
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

    // Структура для хранения геоданных
    struct GeoData
    {
    private:
        constexpr static long NOT_VALID_OFFSET = 0x7FFFFFFF;
        static bool offsetIsValid(long _offset){ return _offset != NOT_VALID_OFFSET; };
        bool isValid = false;        
    public:
        char ip[IP_SIZE] = "";
        char country[COUNTRY_SIZE] = "";
        char city[CITY_SIZE] = "";
        char timezone[TIMEZONE_SIZE] = "";
        int offset = NOT_VALID_OFFSET;
        float latitude = 0.0;
        float longitude = 0.0;

        bool offsetIsValid() const { return offsetIsValid(offset); };
        bool valid() const { return isValid; }
        
        void printTo(Print &p) const
        {
            p.printf("IP: %s\n", ip);
            p.printf("Country: %s\n", country);
            p.printf("City: %s\n", city);
            p.printf("Timezone: %s\n", timezone);
            p.printf("UTC Offset: %d sec (%+.1f hrs)\n", offset, offset / 3600.0);
            p.printf("Location: %.4f, %.4f\n", latitude, longitude);
        }
    };

    // Состояния асинхронного запроса
    enum class State
    {
        Idle,           // Ожидание
        Connecting,     // Подключение к серверу
        SendingRequest, // Отправка запроса
        Receiving,      // Получение ответа
        AllParsed,        // Парсинг данных
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

    enum ProgressPercents {
        None = 0,
        Connecting = 10,
        _oneLineParsed = ( 60 / 7 ),
        //_allLineParsed = HeaderParsed + ( 7 * _oneLineParsed ),
        RequestSended = 20,
        Receiving = 30,
        HeaderParsed = 40,
        AllParsed = HeaderParsed + ( 7 * _oneLineParsed ),
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
         * @param autoSetTime Автоматически установить системное время из заголовка HTTP
         * @param language Двухбуквенный код языка (ru, en и т.д.)
         * @return true если запрос начат успешно
         */
        bool begin(bool autoSetTime = ::NTP_ONLY, const char* language = nullptr);

        /**
         * Получение геолокации (блокирующая)
         * @param autoSetTime Автоматически установить системное время из заголовка HTTP
         * @param language Двухбуквенный код языка (ru, en и т.д.)
         * @param timeout таймаут в милисекундах
         * @return true если успешно получен ответ
         */
        bool getLocation(bool autoSetTime = ::NTP_ONLY, const char* language = nullptr, unsigned long timeout = 10000);

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
        const char * getStateStr() const { return stateToStr( _state ); }

        /**
         * Получить прогресс (0-100)
         */
        int getProgress() const { return _progress; }
        
        /**
         * Получить результат (только после завершения)
         */
        const GeoData& getResult() const { return _data; }
        
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

        /* обёртка для configTime для автоматического конфигурирования */
        void configTime( const char* s1 = "pool.ntp.org", const char * s2 = nullptr, const char * s3 = nullptr) { return ::configTime(0, 0, s1, s2, s3); };


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
        GeoData _data;
        
//         // HTTP-клиент и состояние
#ifdef ESP8266
        //WiFiClient _client;
        //String _responseBuffer;
        int _contentLength;
        bool _headersReceived;
        //int _linesReceived;
        //String _currentLine;
#elif defined(ESP32)
        // Для ESP32 используем HTTPClient асинхронно
        // (будет реализовано ниже)
#endif
        // Для HTTP запроса
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
        //bool parseHttpHeaders();
        bool parseResponseLine(const String& line, int lineIndex);
        time_t parseHttpDate(const String& httpDate) const;
        void setSystemTime(const time_t unixTime, const long usCorrections = 0);
        void _configTime();
        void completeRequest();

    };
}