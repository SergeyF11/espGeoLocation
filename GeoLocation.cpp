#include "GeoLocation.h"
#include <time.h>

namespace GeoLocation
{
    static void setTimeZone(long offset) {
        char tz[17] = {0};
        long displayOffset = -offset; // Инвертируем знак для отображения

        if (offset % 3600) {
            snprintf(tz, sizeof(tz), "UTC%+ld:%02u:%02u", 
                    displayOffset / 3600, 
                    static_cast<unsigned int>(abs((displayOffset % 3600) / 60)), 
                    static_cast<unsigned int>(abs(displayOffset % 60)));
        } else {
            snprintf(tz, sizeof(tz), "UTC%+ld", displayOffset / 3600);
        }

        setenv("TZ", tz, 1);
        tzset();
    }

    String GeoLocation::getConfiguredTimeZone() {
        const char* tz = getenv("TZ");
        if (tz == nullptr) {
            return String("UTC");
        }
        
        // Парсим TZ строку и инвертируем знак для отображения
        String configuredTz = String(tz);
        
        // Если строка содержит UTC, инвертируем знак
        if (configuredTz.startsWith("UTC")) {
            if (configuredTz.length() > 3) {
                char sign = configuredTz.charAt(3);
                if (sign == '+') {
                    configuredTz.setCharAt(3, '-');
                } else if (sign == '-') {
                    configuredTz.setCharAt(3, '+');
                }
                // Если нет знака (например, "UTC0"), добавляем "+"
                else if (sign >= '0' && sign <= '9') {
                    configuredTz = "UTC+" + configuredTz.substring(3);
                }
            }
        }
        
        return configuredTz;
    }

    const char * stateToStr(const State s){
        switch(s){
            case State::Idle: return "Idle"; 
            case State::Connecting: return "Connecting"; 
            case State::SendingRequest: return "SendingRequest"; 
            case State::Receiving: return "Receiving"; 
            case State::AllParsed: return "All Parsed"; 
            case State::SettingTime: return "SettingTime"; 
            case State::Completed: return "Completed";
            default:
                return "Error";
        }
    };
    
    const char* errorToStr(RequestError error) {
        switch(error) {
            case RequestError::None: return "None";
            case RequestError::NoConnection: return "No WiFi connection";
            case RequestError::Timeout: return "Request timeout";
            case RequestError::RateLimited: return "Rate limited";
            case RequestError::ParseError: return "Parse error";
            case RequestError::HttpError: return "HTTP error";
            case RequestError::Unknown: return "Unknown error";
            default: return "Invalid error code";
        }
    }

    GeoLocation::GeoLocation()
        : _state(State::Idle)
        , _error(RequestError::None)
        , _progress(ProgressPercents::None)
        , _timeout(15000) // 15 секунд по умолчанию
        , _startTime(0)
        , _lastActivity(0)
        , _executionTime(0)
        , _useHttpTime(true)
        , _autoSetTime(false)
        , _currentOffset(0)
        , _dataPtr(nullptr)
        , _ipPtr(nullptr)
        , _countryPtr(nullptr)
        , _cityPtr(nullptr)
#ifdef ESP8266
        , _contentLength(-1)
        , _headersReceived(false)
        , _linesReceived(0)
#endif
    {
    }
    
    GeoLocation::~GeoLocation()
    {
        stop();
    }
    
    bool GeoLocation::begin(GeoData* data, bool autoSetTime, const char* language,
                            char* ip, char* country, char* city)
    {
        if (_state != State::Idle && _state != State::Completed && _state != State::Error)
        {
            return false; // Уже выполняется
        }
        
        // Сохраняем указатели
        _dataPtr = data;
        _ipPtr = ip;
        _countryPtr = country;
        _cityPtr = city;
        
        // Очищаем временные буферы
        _tempIp[0] = '\0';
        _tempCountry[0] = '\0';
        _tempCity[0] = '\0';
        _tempTimezone = TimeZone();
        _tempLatitude = 0.0;
        _tempLongitude = 0.0;
        
        // Сброс состояния
        _resultData = GeoData();
        _error = RequestError::None;
        _progress = ProgressPercents::None;
        _startTime = millis();
        _lastActivity = _startTime;
        _executionTime = 0;
        _autoSetTime = autoSetTime;
        _language = language ? language : "";

        if (autoSetTime) _useHttpTime = true;
    
        _linesReceived = 0;
        _currentLine = "";
        _headersParsed = false;
        _httpDateSet = false;
        
#ifdef ESP8266
        _contentLength = -1;
        _headersReceived = false;
#endif
        
        // Проверка WiFi
        if (WiFi.status() != WL_CONNECTED)
        {
            setError(RequestError::NoConnection);
            setState(State::Error);
            return false;
        }
        
        // Подключаемся к серверу
        if (!connectToServer())
        {
            setError(RequestError::HttpError);
            setState(State::Error);
            return false;
        }
        
        setState(State::Connecting);
        setProgress(ProgressPercents::Connecting);
        
        // Отправляем запрос
        sendHttpRequest();
        setProgress(ProgressPercents::RequestSended);
        
        return true;
    }
    
    void GeoLocation::stop()
    {
        if (_client.connected())
        {
            _client.stop();
        }
        
        setState(State::Idle);
    }
    
    bool GeoLocation::connectToServer()
    {
        return _client.connect("ip-api.com", 80);
    }

    void GeoLocation::process()
    {
        if (_state == State::Idle || _state == State::Completed || _state == State::Error)
            return;
        
        // Проверка таймаута
        if (millis() - _lastActivity > _timeout)
        {
            setError(RequestError::Timeout);
            setState(State::Error);
            return;
        }
        
        // Обработка текущего состояния
        switch (_state)
        {
            case State::Connecting:
                // Проверяем, подключились ли мы
                if (_client.connected())
                {
                    setState(State::Receiving);
                    setProgress(ProgressPercents::Receiving);
                }
                else if (millis() - _startTime > 5000) // 5 секунд на подключение
                {
                    setError(RequestError::Timeout);
                    setState(State::Error);
                }
                break;
                
            case State::Receiving:
                processResponse();
                break;
                
            case State::AllParsed:
            case State::SettingTime:
                completeRequest();
                break;
                
            default:
                break;
        }
    }
    
    void GeoLocation::setState(State newState)
    {
        if (_state != newState)                            
        {
            _state = newState;
            _lastActivity = millis();
            
            if (_progressCallback)
            {
                _progressCallback(_state, _progress);
            }
        }
    }
    
    void GeoLocation::setProgress(int progress)
    {
        if (_progress != progress)
        {
            _progress = progress;
            
            if (_progressCallback)
            {
                _progressCallback(_state, _progress);
            }
        }
    }
    
    void GeoLocation::setError(RequestError error)
    {
        _error = error;
    }
    
    void GeoLocation::sendHttpRequest()
    {
        String request = "GET /line/?fields=status,country,city,lat,lon,timezone,offset,query";
        if (_language.length() == 2)
        {
            request += "&lang=";
            request += _language;
        }
        request += " HTTP/1.1\r\n";
        request += "Host: ip-api.com\r\n";
        request += "Connection: close\r\n";
        request += "\r\n";
        
        _client.print(request);
    }

    void GeoLocation::processResponse()
    {
        // Читаем данные, если они есть
        while (_client.available())
        {
            char c = _client.read();
            
            if (c == '\n')
            {
                // Конец строки
                if (!_headersParsed)
                {
                    // Парсим заголовки
                    if (_currentLine.length() == 0)
                    {
                        // Пустая строка - конец заголовков
                        _headersParsed = true;
                        setProgress(ProgressPercents::HeaderParsed);
                    }
                    else
                    {
                        // Ищем заголовок Date
                        if (_useHttpTime && !_httpDateSet && _currentLine.startsWith("Date:"))
                        {
                            auto httpTime = parseHttpDate(_currentLine.substring(6));
                            if (httpTime > LIKE_VALID_TIME)
                            {
                                setSystemTime(httpTime, (httpCorrectionMs + _executionTime) * 1000);
                                _httpDateSet = true;
                            }
                        }
                    }
                }
                else
                {
                    // Парсим данные
                    if (_currentLine.length() > 0)
                    {
                        if (parseResponseLine(_currentLine, _linesReceived))
                        {
                            _linesReceived++;
                            
                            // Обновляем прогресс
                            int newProgress = ProgressPercents::HeaderParsed + (_linesReceived * ProgressPercents::_oneLineParsed);
                            setProgress(newProgress);
                            
                            if (_linesReceived >= Line::AllLine)
                            {
                                setState(State::AllParsed);
                                
                                // Сохраняем распарсенные данные
                                saveParsedData();
                                
                                // Устанавливаем системное время, если нужно
                                if (_autoSetTime && _tempTimezone.isValid())
                                {
                                    setState(State::SettingTime);    
                                    _configTime();
                                }
                                
                                setProgress(ProgressPercents::Completed);
                                break;
                            }
                        }
                        else
                        {
                            // Ошибка парсинга
                            setError(RequestError::ParseError);
                            setState(State::Error);
                            return;
                        }
                    }
                }
                
                _currentLine = "";
            }
            else if (c != '\r')
            {
                _currentLine += c;
            }
        }
        
        // Проверяем, завершено ли соединение
        if (!_client.connected() && _linesReceived < 7)
        {
            if (_linesReceived > 0)
            {
                // Не все данные получены, но соединение закрыто
                setError(RequestError::HttpError);
                setState(State::Error);
            }
        }
    }

    void GeoLocation::saveParsedData()
    {
        // Сохраняем данные в указанную структуру GeoData
        GeoData* targetData = _dataPtr ? _dataPtr : &_resultData;
        
        targetData->latitude = _tempLatitude;
        targetData->longitude = _tempLongitude;
        targetData->timezone = _tempTimezone;
        
        // Копируем дополнительные данные, если указатели заданы
        if (_ipPtr && _tempIp[0] != '\0') {
            strlcpy(_ipPtr, _tempIp, IP_SIZE);
        }
        
        if (_countryPtr && _tempCountry[0] != '\0') {
            strlcpy(_countryPtr, _tempCountry, COUNTRY_SIZE);
        }
        
        if (_cityPtr && _tempCity[0] != '\0') {
            strlcpy(_cityPtr, _tempCity, CITY_SIZE);
        }
    }

    bool GeoLocation::parseResponseLine(const String& line, int lineIndex)
    {
        if (line.length() == 0) {
            return false; // Пустая строка
        }
        
        #if defined(ESP32)
        log_i("Parsing line \"%s\"", line.c_str());
        #else 
        #ifdef ERROR_DEBUG
        Serial.printf("Parsing line \"%s\"\n", line.c_str());
        #endif
        #endif

        switch (lineIndex)
        {
            case Line::Status:
                return strncmp("success", line.c_str(), sizeof("success")-1) == 0;

            case Line::Country: // country
                if (_countryPtr) {
                    strlcpy(_tempCountry, line.c_str(), COUNTRY_SIZE);
                }
                return true;
                
            case Line::City: // city
                if (_cityPtr) {
                    strlcpy(_tempCity, line.c_str(), CITY_SIZE);
                }
                return true;
                
            case Line::Lat: // lat
                _tempLatitude = line.toFloat();
                return true;
                
            case Line::Lon: // lon
                _tempLongitude = line.toFloat();
                return true;
                
            case Line::TimeZoneLine: // timezone
                strlcpy(_tempTimezone.tz, line.c_str(), TIMEZONE_SIZE);
                return true;
                
            case Line::Offset: // offset
                _tempTimezone.offset = line.toInt();
                return true;
                
            case Line::MyIP: // IP
                if (_ipPtr) {
                    strlcpy(_tempIp, line.c_str(), IP_SIZE);
                }
                return true;
                
            default:
                return false;
        }
    }
    
    time_t GeoLocation::parseHttpDate(const String& httpDate) const
    {
        time_t httpTime = 0;
        const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
        
        struct tm tm = {0};
        char monthStr[4] = {0};
        
        // Парсим строку формата "Mon, 25 Dec 2023 14:30:45 GMT"
        int parsed = sscanf(httpDate.c_str(), 
                        "%*3s, %d %3s %d %d:%d:%d",
                        &tm.tm_mday, monthStr, &tm.tm_year,
                        &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
        
        if (parsed == 6)
        {
            // Находим месяц
            for (int i = 0; i < 12; i++)
            {
                if (strncmp(monthStr, months[i], 3) == 0)
                {
                    tm.tm_mon = i;
                    break;
                }
            }
            
            tm.tm_year -= 1900; // Год с 1900
            
            httpTime = mktime(&tm);
        }
        return httpTime;
    }

    void GeoLocation::setSystemTime(const time_t unixTime, const long usCorrections)
    {
        struct timeval tv;

        if (_tempTimezone.isValid())
        {
            #if defined(ESP32)
            log_i("Correct unix time to local offset %d", _tempTimezone.offset);
            #else 
            #ifdef ERROR_DEBUG
            Serial.printf("Correct unix time to local offset %d\n", _tempTimezone.offset);
            #endif
            #endif
        
            tv = {(unixTime + _tempTimezone.offset), usCorrections};
        }
        else
        {
            tv = {unixTime, usCorrections};
        }
        
        settimeofday(&tv, nullptr);
    }

    void GeoLocation::_configTime()
    {
        if (!_tempTimezone.isValid()) {
            return;
        }

        const bool isOffsetValid = (_currentOffset != 0);
        const bool hasOffsetChanged = (_currentOffset != _tempTimezone.offset);

        // Если смещение уже установлено и не изменилось
        if (isOffsetValid && !hasOffsetChanged) {
            #if defined(ESP32)
            log_i("Is configured already");
            #else 
            #ifdef ERROR_DEBUG
            Serial.println("Is configured already");
            #endif
            #endif
            return;
        }

        // Логирование изменения смещения
        #if defined(ESP32)
        log_i("%s time offset %d", 
            isOffsetValid ? "Reconfigure" : "Configure", 
            _tempTimezone.offset);
        #else 
        #ifdef ERROR_DEBUG
        Serial.printf("%s time offset %d\n", 
                    isOffsetValid ? "Reconfigure" : "Configure", 
                    _tempTimezone.offset);
        #endif
        #endif

        // Если смещение уже было установлено и изменилось, сохраняем текущее время
        time_t currentUnixTime = 0;
        if (isOffsetValid && hasOffsetChanged) {
            currentUnixTime = time(nullptr) - _currentOffset;
        }

        // Обновляем смещение и часовой пояс
        _currentOffset = _tempTimezone.offset;
        setTimeZone(_tempTimezone.offset);

        // Восстанавливаем системное время при изменении смещения
        if (isOffsetValid && hasOffsetChanged) {
            setSystemTime(currentUnixTime);
        }

        // Пытаемся получить локальное время (неблокирующе)
        struct tm timeinfo;
        if (getLocalTime(&timeinfo, 5000)) {
            // Время успешно установлено
        }
    }

    void GeoLocation::completeRequest()
    {
        // Закрываем соединение
        if (_client.connected())
        {
            _client.stop();
        }
        
        _executionTime = millis() - _startTime;
        
        setState(State::Completed);

        // Вызываем коллбэк завершения
        if (_completeCallback)
        {
            _completeCallback(getResult(), RequestError::None);
        }
    }

    bool GeoLocation::getLocation(GeoData* data, bool autoSetTime, const char* language,
                                  unsigned long timeout,
                                  char* ip, char* country, char* city)
    {
        if (isRunning()) {
            return false; // Уже выполняется асинхронно
        }
        
        // Сохраняем текущий таймаут
        unsigned long originalTimeout = _timeout;
        
        // Устанавливаем таймаут для блокирующего вызова
        if (timeout > 0) {
            setTimeout(timeout);
        }
        
        // Временно отключаем колбэки для блокирующего вызова
        ProgressCallback savedProgressCallback = _progressCallback;
        CompleteCallback savedCompleteCallback = _completeCallback;
        _progressCallback = nullptr;
        _completeCallback = nullptr;
        
        bool success = false;
        
        if (begin(data, autoSetTime, language, ip, country, city)) {
            unsigned long startTime = millis();
            
            // Основной цикл ожидания завершения
            while (isRunning()) {
                process();
                
                // Проверка таймаута
                if (timeout > 0 && (millis() - startTime) > timeout) {
                    setError(RequestError::Timeout);
                    stop();
                    break;
                }
                
                // Небольшая задержка, чтобы не перегружать процессор
                delay(1);
            }
            
            success = (_state == State::Completed);
        }
        
        // Восстанавливаем колбэки
        _progressCallback = savedProgressCallback;
        _completeCallback = savedCompleteCallback;
        
        // Восстанавливаем таймаут
        _timeout = originalTimeout;
        
        // Вызываем сохранённый коллбэк завершения, если есть
        if (success && savedCompleteCallback) {
            savedCompleteCallback(getResult(), RequestError::None);
        }
        
        return success;
    }
}