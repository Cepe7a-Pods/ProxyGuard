# 🛡 ProxyGuard

**Автоматический MTProto прокси-менеджер для Telegram (Android)**

Приложение запускает локальный MTProto relay на `127.0.0.1:1080`, автоматически
собирает рабочие прокси из публичных источников, измеряет пинг и прозрачно
переключается при падении прокси. Telegram настраивается один раз и забывает о проблеме.

---

## Архитектура

```
Telegram (MTProto → 127.0.0.1:1080)
    │
    ▼
LocalRelayServer (port 1080)
    │  AES-CTR расшифровка (bridge secret)
    │  AES-CTR перешифровка (proxy secret)
    ▼
External MTProto Proxy (из GitHub-списков)
    │
    ▼
Telegram API
```

Ключевая идея: relay перешифровывает только **внешний обфускационный слой** (AES-256-CTR).
Внутреннее MTProto-шифрование Telegram остаётся нетронутым — прокси его не видит.

---

## Настройка (один раз)

1. Установить и запустить ProxyGuard
2. Скопировать **секрет** из приложения
3. В Telegram: Настройки → Данные → Прокси → Добавить прокси
   - Тип: **MTProto** (не SOCKS5!)
   - Адрес: `127.0.0.1`
   - Порт: `1080`
   - Секрет: вставить скопированное
4. Нажать **Запустить** в ProxyGuard

---

## Сборка

```bash
./gradlew assembleDebug
```

Требования: Android Studio Hedgehog+, Kotlin 2.0+, Min SDK 26 (Android 8.0)

---

## Статус реализации

- [x] MTProto обфускация (AES-256-CTR, random-padded / dd-prefix)
- [x] Локальный TCP relay сервер
- [x] Пул прокси с сортировкой по пингу
- [x] MTProto-level валидатор (не просто TCP-пинг)
- [x] Парсинг GitHub-источников (tg://, raw text)
- [x] ForegroundService + автозапуск при загрузке
- [ ] FakeTLS (ee-prefix) — в разработке
- [ ] Telegram Bot API для групп с прокси

---

## Технические детали

### Протокол обфускации (dd-prefix)

Клиент (Telegram) отправляет 64-байтовый nonce:
- `[0..8]`   — случайные байты
- `[8..40]`  — ключевой материал
- `[40..56]` — IV
- `[56..60]` — зашифрованный protocol tag (0xdddddddd)
- `[60..64]` — зарезервировано

Ключи: `enc_key = SHA256(secret + nonce[8:40])`, `dec_key = SHA256(secret + reverse(nonce[8:40]))`

Relay поддерживает 4 AES-CTR потока на соединение (2 направления × 2 ноги relay).

---

MIT License
