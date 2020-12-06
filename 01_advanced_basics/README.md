# 01_advanced_basics

использование:
```
(venv) >python log_analyzer.py -h
usage: log_analyzer.py [-h] [--config CONFIG]

optional arguments:
  -h, --help       show this help message and exit
  --config CONFIG  path to json config file
```

дефолтный конфиг:
```
{
"REPORT_SIZE": 1000,        # суммарное время обработки запросов для попадания в отчет
"REPORT_DIR": "reports",    # директория для готовыйх html отчетов
"ERROR_THRESHOLD": 20,      # порог для оповещения об ошибках в отчете, % относительно общего числа записей
"LOG_DIR": "log",           # источник сырых nginx отчетов
"LOGGER_FILE": null         # путь к файлу лога, при null лог идет в stdout
}
```
при отсутствии параметра в конфиге подставляется дефолтное значение



