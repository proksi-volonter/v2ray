# V2Ray-Plugin Multi-Port Auto-Rotator

Продвинутая автоматизированная система для динамической ротации портов и обфускации через WebSocket с использованием ShadowSocks и плагина V2Ray на Ubuntu 22.04.

## Особенности

- **Динамическая ротация основных портов**: Автоматически меняет 7 открытых портов каждые 30 минут в случайном диапазоне. Запускается *сразу после установки*, а затем по расписанию.
- **Динамическая ротация портов обфускации**: Каждый час система выбирает 7 *новых* случайных UDP-портов (с проверкой занятости), *открывает* их и отправляет на них мусорный трафик для усложнения детекции. Предыдущие порты обфускации закрываются.
- **Обфускация WebSocket**: Использует плагин V2Ray с случайными путями WebSocket для маскировки основного трафика
- **Автоматическая безопасность**: Реализует продвинутые меры безопасности, включая защиту от SUID/SGID-атак, совместимость с файловыми системами только для чтения и профили безопасности systemd
- **Самовосстановление**: Автоматическое резервное копирование, проверки целостности и механизмы восстановления
- **Обфускационные фреймы**: Периодическая отправка нестандартных фреймов для повышения уровня безопасности
- **Высокая доступность**: Несколько экземпляров сервиса с автоматическим перезапуском и отказоустойчивостью
- **Использование уникальных маркеров heredoc**: Устранена критическая синтаксическая ошибка, связанная с вложенными блоками heredoc
- **Правильная подстановка переменных**: Исправлена ошибка подстановки переменных в генерируемом скрипте
- **Мягкие политики безопасности**: Использование `ProtectSystem=strict` вместо `full` в юнитах systemd для обеспечения возможности записи в `/etc`.

## Системные требования

- Ubuntu 22.04 LTS
- Архитектура x86_64
- Не менее 100 МБ свободного места на диске
- Права root/sudo
- Подключение к интернету

## Установка

### Быстрая установка
```bash
curl -sSL https://raw.githubusercontent.com/proksi-volonter/v2ray/refs/heads/main/V2Ray-Plugin%20Multi-Port.sh | sudo bash

Что устанавливается
V2Ray Plugin: Последняя версия автоматически загружается с GitHub
ShadowSocks Server: С бэкендом libev
Скрипты конфигурации:
/usr/local/bin/start-v2ray-multi.sh - Основной скрипт конфигурации и ротации основных портов
/usr/local/bin/send-nonstandard-frame.sh - Скрипт конфигурации и ротации портов обфускации
Системные юниты (systemd):
Шаблон сервиса ss-server-v2ray@.service для каждого основного порта
Основной сервис v2ray-multi.service с таймером
Сервис обфускации send-nonstandard-frame.service с таймером
____________________________________________________________

Конфигурация
Переменные окружения
V2RAY_NUM_PORTS: Количество используемых основных портов (по умолчанию: 7)
ROTATE_PW: Принудительно менять пароль основного сервиса (1 для включения, по умолчанию: случайное значение)
Файлы и расположения
Конфигурации основных портов: /etc/shadowsocks-libev/*.json (по одной на порт)
Пароли: /etc/v2ray_passwd (зашифрован)
Список основных портов: /etc/v2ray_ports.list
Список текущих портов обфускации: /tmp/current_obf_ports.list
Логи основного сервиса: /var/log/v2ray-multi.log
Логи сервиса обфускации: /var/log/send-nonstandard-frame.log
Резервные копии: /var/tmp/v2ray_* (с SHA-проверкой)
______________________________________________________________

Функции безопасности
Шифрование: Шифр ChaCha20-IETF-Poly1305 для основного трафика
Обфускация: Случайные пути WebSocket из 8 доступных вариантов для основного трафика
Обфускация трафика: Активное открытие UDP-портов и отправка мусорного трафика для усложнения детекции
Закрепление системы:
Включено NoNewPrivileges
Защита MemoryDenyWriteExecute
PrivateTmp и PrivateDevices
Ограничения CapabilityBoundingSet
Резервное копирование и восстановление: Резервные копии с SHA-проверкой и автоматическим восстановлением
Мягкие политики безопасности: Использование ProtectSystem=strict для юнитов systemd, позволяющее запись в /etc.
Автоматическое снятие атрибута immutable: Перед записью в файлы удаляются атрибуты, блокирующие запись.
______________________________________________________________

Проверка статуса
# Просмотр статуса таймеров
sudo systemctl status v2ray-multi.timer
sudo systemctl status send-nonstandard-frame.timer

# Просмотр таймеров
sudo systemctl list-timers --all | grep -E "(v2ray-multi|send-nonstandard-frame)"

# Просмотр активных сервисов
sudo systemctl list-units --type=service --state=active | grep -E "(ss-server-v2ray@|send-nonstandard-frame)"

# Просмотр основных логов
sudo journalctl -u v2ray-multi.service -f
sudo journalctl -u send-nonstandard-frame.service -f

# Просмотр файлов логов
sudo tail -f /var/log/v2ray-multi.log
sudo tail -f /var/log/send-nonstandard-frame.log

Шаги отладки
Проверьте системные логи: sudo journalctl -xe
Проверьте сервисы: sudo systemctl --failed
Проверьте место на диске: df -h
Просмотрите файлы конфигурации в /etc/shadowsocks-libev/ и /tmp/current_obf_ports.list
Проверьте, запущены ли процессы socat на портах обфускации: sudo netstat -ulnp | grep socat или sudo lsof -i -P -n | grep socat
______________________________________________________________

Чтобы удалить систему
# Остановить и отключить сервисы
sudo systemctl stop v2ray-multi.timer send-nonstandard-frame.timer
sudo systemctl disable v2ray-multi.timer send-nonstandard-frame.timer
sudo systemctl stop v2ray-multi.service send-nonstandard-frame.service
sudo systemctl disable v2ray-multi.service send-nonstandard-frame.service

# Убить возможные оставшиеся процессы socat
sudo pkill -f "socat UDP-LISTEN"

# Удалить сервисы и скрипты
sudo rm -f /etc/systemd/system/v2ray-multi.*
sudo rm -f /etc/systemd/system/send-nonstandard-frame.*
sudo rm -f /usr/local/bin/start-v2ray-multi.sh
sudo rm -f /usr/local/bin/send-nonstandard-frame.sh
sudo rm -f /usr/bin/v2ray-plugin

# Удалить файлы конфигурации и состояния
sudo rm -rf /etc/shadowsocks-libev/
sudo rm -f /etc/v2ray_passwd
sudo rm -f /etc/v2ray_ports.list
sudo rm -f /tmp/current_obf_ports.list

# Перезагрузить systemd
sudo systemctl daemon-reload
sudo systemctl reset-failed
____________________________________________________________________

Лицензия
Этот проект с открытым исходным кодом доступен по лицензии MIT.

Поддержка
Для вопросов и поддержки, пожалуйста, откройте issue в репозитории.
