#include "GeoLocation.h"
#include <time.h>


namespace GeoLocation
{
    static void setTimeZone(long offset) {
        char tz[17] = {0};

        if (offset % 3600) {
            snprintf(tz, sizeof(tz), "UTC%ld:%02u:%02u", 
                    offset / 3600, 
                    static_cast<unsigned int>(abs((offset % 3600) / 60)), 
                    static_cast<unsigned int>(abs(offset % 60)));
        } else {
            snprintf(tz, sizeof(tz), "UTC%ld", offset / 3600);
        }

        setenv("TZ", tz, 1);
        tzset();
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
        , _currentOffset(GeoData::NOT_VALID_OFFSET)
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
    
    bool GeoLocation::begin(bool autoSetTime, const char* language)
    {
        if (_state != State::Idle && _state != State::Completed && _state != State::Error)
        {
            return false; // Уже выполняется
        }
        
        // Сброс состояния
        _data = GeoData();
        _error = RequestError::None;
        _progress = ProgressPercents::None;
        _startTime = millis();
        _lastActivity = _startTime;
        _executionTime = 0;
        _autoSetTime = autoSetTime;
        _language = language ? language : "";

        if ( autoSetTime ) _useHttpTime = true;
    
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
        setProgress(ProgressPercents::RequestSended); //20);
        
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
            // парсим строку
                processResponse();
                break;
                
            case State::AllParsed:
            case State::SettingTime:
                // Парсинг уже выполнен в processResponse
                completeRequest();
                //setState(State::Completed);
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
    String request = "GET /line/?fields=country,city,lat,lon,timezone,offset,query";
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

// устанавливает State::Parsing или State::Error
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
                        if ( httpTime > LIKE_VALID_TIME ){

                            setSystemTime(httpTime, ( httpCorrectionMs + _executionTime)*1000 );

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
                        int newProgress =  ProgressPercents::HeaderParsed + ( _linesReceived * ProgressPercents::_oneLineParsed );
                         //40 + (_linesReceived * 60 / 7);
                        setProgress(newProgress);
                        
                        if (_linesReceived >= 7)
                        {
                            setState(State::AllParsed);
                            // Все данные получены
                            _data.isValid = true;
                            
                            // Устанавливаем системное время, если нужно
                            if (_autoSetTime /* &&  _data.offsetIsValid() _data.offset != 0xFFFF */ )
                            {
                                setState(State::SettingTime);    
                                _configTime();
                            }
                            //setProgress( ProgressPercents::AllParsed); //100);
                            setProgress( ProgressPercents::Completed);
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

    void GeoLocation::completeRequest()
    {
        // Закрываем соединение
        if (_client.connected())
        {
            _client.stop();
        }
        
        _executionTime = millis() - _startTime;
        
        setState(State::Completed);
        //setProgress(ProgressPercents::Completed);

        // Вызываем коллбэк завершения
        if (_completeCallback)
        {
            _completeCallback(_data, RequestError::None);
        }
    }

    bool GeoLocation::parseResponseLine(const String& line, int lineIndex)
    {
        if (line.length() == 0) {
            return false; // Пустая строка
        }
        
        switch (lineIndex)
        {
            case 0: // country
                strlcpy(_data.country, line.c_str(), COUNTRY_SIZE);
                return true;
                
            case 1: // city
                strlcpy(_data.city, line.c_str(), CITY_SIZE);
                return true;
                
            case 2: // lat
                _data.latitude = line.toFloat();
                return true;
                
            case 3: // lon
                _data.longitude = line.toFloat();
                return true;
                
            case 4: // timezone
                strlcpy(_data.timezone, line.c_str(), TIMEZONE_SIZE);
                return true;
                
            case 5: // offset
                _data.offset = line.toInt();
                return true;
                
            case 6: // IP
                strlcpy(_data.ip, line.c_str(), IP_SIZE);
                return true;
                
            default:
                return false;
        }
    }
    
    time_t GeoLocation::parseHttpDate(const String& httpDate) const
    {
        time_t httpTime = 0;
        //  надежный парсер HTTP-даты
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
            
            // // Проверяем корректность времени
            // if (unixTime > 1609459200) // После 1 января 2021
            // {
            //     setSystemTime(unixTime);
            // }
        }
        return httpTime;
    }

    void GeoLocation::setSystemTime(const time_t unixTime , const long usCorrections ){
        struct timeval tv;

        if ( GeoData::offsetIsValid( _currentOffset ) ){
            #if defined(ESP32)
            log_i("Correct unix time to local offset %lu", _currentOffset);
            #else 
            #ifdef ERROR_DEBUG
            Serial.printf("Correct unix time to local offset %lu\n", _currentOffset);
            #endif
            #endif
        
            tv = { (unixTime + _currentOffset), usCorrections };
        } else 
            tv = {unixTime, usCorrections };
        settimeofday(&tv, nullptr);
        
    }

    

    void GeoLocation::_configTime()
    {
        if (!_data.offsetIsValid()) {
            return;
        }

        const bool isOffsetValid = GeoData::offsetIsValid(_currentOffset);
        const bool hasOffsetChanged = (_currentOffset != _data.offset);

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
            _data.offset);
        #else 
        #ifdef ERROR_DEBUG
        Serial.printf("%s time offset %d\n", 
                    isOffsetValid ? "Reconfigure" : "Configure", 
                    _data.offset);
        #endif
        #endif

        // Если смещение уже было установлено и изменилось, сохраняем текущее время
        time_t currentUnixTime = 0;
        if (isOffsetValid && hasOffsetChanged) {
            currentUnixTime = time(nullptr) - _currentOffset;
        }

        // Обновляем смещение и часовой пояс
        _currentOffset = _data.offset;
        setTimeZone(-_data.offset);

        // Восстанавливаем системное время при изменении смещения
        if (isOffsetValid && hasOffsetChanged) {
            setSystemTime(currentUnixTime);
        }

        // Пытаемся получить локальное время (неблокирующе)
        struct tm timeinfo;
        if (getLocalTime(&timeinfo, 5000)) {
            // Время успешно установлено
            // Можно добавить дополнительную логику при успешной синхронизации
        }
    }


    bool GeoLocation::getLocation(bool autoSetTime, const char* language, unsigned long timeout)
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
        
        if (begin(autoSetTime, language)) {
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
            savedCompleteCallback(_data, RequestError::None);
        }
        
        return success;
    }

}