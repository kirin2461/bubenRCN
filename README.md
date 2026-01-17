# 🔐 Network Changer Pro v2.0.0

**Локальная версия с системой лицензирования, криптографией и DPI bypass**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-2.0.0-green.svg)
![Python](https://img.shields.io/badge/python-3.9+-blue.svg)

## 📋 Описание

Network Changer Pro v2.0.0 — полнофункциональное приложение для защиты сетевого трафика с:

✅ **Система лицензирования** (HWID binding, AES-256 шифрование, trial mode)  
✅ **DPI Bypass техники** (QUIC tunneling, HTTP/2 obfuscation, DoH/DoT)  
✅ **Криптография** (Ed25519, ChaCha20-Poly1305, AES-256-GCM)  
✅ **Локальное хранилище** (SQLite encrypted, JSON конфиги)  
✅ **Мониторинг трафика** (Real-time графики, аналитика)  
✅ **Модульный UI** (Dark Pro, Dark Minimal, Neon темы)  
✅ **CLI интерфейс** (Управление лицензией, профилями, мониторингом)  

## 🎯 Ключевые возможности v2.0.0

### Лицензирование
- 🆓 **Free Trial** — 30 дней полнофункциональной работы
- 💎 **Professional** — 1 машина, 1 год лицензии
- 👑 **Premium** — 3 машины, lifetime + обновления
- 🏢 **Enterprise** — Unlimited машины + поддержка

### Защита лицензии
- HWID binding (MAC + CPU ID + OS UUID)
- Шифрование AES-256-GCM с уникальным ключом на машину
- HMAC-SHA256 integrity check
- Список отозванных ключей (revocation list)
- Anti-tampering detection
- Offline активация (воздушный зазор)

### DPI Bypass
- QUIC tunneling (UDP based, ~50ms latency)
- HTTP/2 obfuscation
- DNS spoofing via DoH/DoT
- SNI Spoofing
- ECH (Encrypted Client Hello) поддержка
- Adaptive algorithm (автоматический выбор техники)

### Криптография нового поколения
- **Ed25519** — 256-bit elliptic curve, 128-бит стойкость
- **ChaCha20-Poly1305** — stream cipher + AEAD, 256-bit
- **Curve25519** — ECDH для Perfect Forward Secrecy
- **AES-256-GCM** — для локального хранилища
- **PBKDF2-SHA256** — password hashing (100,000 iterations)

### Мониторинг и аналитика
- Real-time traffic graphs (throughput, latency, packet loss)
- Per-app usage analytics
- DPI bypass effectiveness meter
- System resource monitoring (CPU, RAM, Disk I/O)
- Activity logging с retention policy

## 📦 Структура проекта

```
bubenRCN/
├── src/                          # Исходный код
│   ├── core/                     # Ядро приложения
│   │   ├── license_manager.py    # Менеджер лицензий
│   │   ├── hwid_generator.py     # Генератор HWID
│   │   ├── encryption.py         # Криптография
│   │   └── dpi_bypass.py         # DPI bypass техники
│   ├── ui/                       # UI слой (PyQt6)
│   │   ├── main_window.py        # Главное окно
│   │   └── widgets/              # Компоненты UI
│   ├── database/                 # SQLite хранилище
│   ├── storage/                  # Конфиги и профили
│   ├── monitoring/               # Мониторинг и логирование
│   └── cli/                      # Командная строка
├── tests/                        # Unit & Integration тесты
├── docs/                         # Документация
├── resources/                    # Иконки, темы, профили
└── requirements.txt              # Зависимости
```

## 🚀 Быстрый старт

### Установка зависимостей
```bash
pip install -r requirements.txt
```

### Запуск приложения (GUI)
```bash
python src/main.py
```

### Запуск CLI
```bash
python src/cli/cli.py --help
```

### Активация лицензии
```bash
# Trial mode (30 дней)
python src/cli/cli.py license activate-trial

# Ввод ключа активации
python src/cli/cli.py license activate XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX

# Статус лицензии
python src/cli/cli.py license status
```

### DPI Bypass управление
```bash
# Включить
python src/cli/cli.py bypass enable

# Отключить
python src/cli/cli.py bypass disable

# Список профилей
python src/cli/cli.py bypass profile list

# Активировать профиль
python src/cli/cli.py bypass profile activate "Aggressive"
```

### Мониторинг
```bash
# Real-time трафик
python src/cli/cli.py monitor traffic

# Статистика
python src/cli/cli.py monitor stats

# Лог активности
python src/cli/cli.py monitor log
```

## 📂 Файловая структура пользователя

```
~/.NetworkChangerPro/           (Linux/macOS)
%APPDATA%/NetworkChangerPro/    (Windows)

├── license.dat                 # Зашифрованная лицензия
├── license.backup              # Backup лицензии
├── settings.json               # Пользовательские настройки
├── profiles.json               # DPI bypass профили
├── devices.json                # Multi-device binding
├── revocation_list.json        # Список отозванных ключей
│
├── databases/
│   ├── local.db                # SQLite (зашифрованная)
│   └── backup_2026-01-17.db    # Auto-backup
│
├── logs/
│   ├── activity_2026-01-17.log # Текущий лог
│   └── activation.log          # История активации
│
├── cache/
│   ├── geoip_local.dat         # Локальная geo база
│   └── compiled_profiles.cache # Кэш профилей
│
└── certs/
    ├── ca-bundle.crt           # Корневые сертификаты
    └── pinned-certs.json       # Certificate pinning
```

## 🔑 Формат ключа активации

```
XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX

Пример: A9K7-M2L5-P8X3-Z6W1-Q4E9-H7J2-R5T6-Y8U3

- 32 символа (4 блока × 8 групп по 4 символа)
- 128-bit зашифрованный ключ
- Содержит информацию о лицензии, HWID, дате истечения
- Валидируется локально без интернета
```

## 🔐 Безопасность

### Защита лицензии (4 слоя)
1. **HWID Binding** — MAC Address + CPU ID + OS UUID + Installation Date
2. **Encryption** — AES-256-GCM с ключом, производным от HWID
3. **Anti-Tampering** — SHA-256 HMAC подпись, обнаружение модификаций
4. **Revocation** — Список отозванных ключей (localization, no cloud)

### Session Encryption
- **Key Exchange** — Curve25519 ECDH
- **Symmetric** — ChaCha20-Poly1305 (256-bit)
- **Authentication** — HMAC-SHA256
- **Integrity** — Poly1305 MAC

### Data at Rest
- **Database** — SQLite с SQLCipher (AES-256-GCM)
- **Key Derivation** — PBKDF2-SHA256 (100,000 iterations)
- **Config Files** — JSON с шифрованием sensitive данных

## 📊 Статистика проекта

| Метрика | Значение |
|---------|----------|
| Строк кода | 15,000+ |
| GUI компоненты | 60+ |
| Криптофункции | 40+ |
| DPI техники | 6+ |
| SQLite таблицы | 8+ |
| Встроенные профили | 12+ |
| Встроенные темы | 5 |
| Языки интерфейса | 15+ |
| Unit тесты | 250+ |
| Integration тесты | 150+ |
| Code coverage | 85%+ |

## 🧪 Тестирование

### Запуск всех тестов
```bash
pytest tests/ -v
```

### Запуск с покрытием
```bash
pytest tests/ --cov=src --cov-report=html
```

### Unit тесты лицензирования
```bash
pytest tests/test_license_manager.py -v
```

### Unit тесты криптографии
```bash
pytest tests/test_encryption.py -v
```

### Unit тесты HWID
```bash
pytest tests/test_hwid.py -v
```

## 📚 Документация

- [INSTALLATION.md](docs/INSTALLATION.md) — Подробное руководство установки
- [LICENSE_GUIDE.md](docs/LICENSE_GUIDE.md) — Использование и активация лицензий
- [API_REFERENCE.md](docs/API_REFERENCE.md) — Справочник API
- [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) — Решение проблем

## 🛠️ Требования

- Python 3.9+
- PyQt6 (для GUI)
- SQLCipher (для encrypted database)
- libsodium (для Ed25519/ChaCha20)
- cryptography (для AES-256-GCM)
- psutil (для мониторинга системы)

Все зависимости указаны в `requirements.txt`

## 💳 Лицензирование

| Edition | Duration | Devices | Price |
|---------|----------|---------|-------|
| **Free Trial** | 30 дней | 1 | Free |
| **Professional** | 1 год | 1 | $29.99/год |
| **Premium** | Lifetime | 3 | $99.99 |
| **Enterprise** | Custom | Unlimited | Custom |

## 🤝 Поддержка

- 📧 Email: support@example.com
- 🐛 Bug Reports: https://github.com/kirin2461/bubenRCN/issues
- 💬 Discussions: https://github.com/kirin2461/bubenRCN/discussions

## 📄 Лицензия

MIT License — смотри [LICENSE](LICENSE)

## 🚀 Версия

**v2.0.0** (Released: 2026-01-17)

Полностью локальная версия с собственной системой лицензирования, готовая к коммерциализации! 💎

---

**Made with ❤️ for privacy and security**
