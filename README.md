# rate-limit-shield

Защита от DDoS/брутфорса через rate limiting на Python (Flask) —
алгоритм Sliding Window, конфигурируемые лимиты по маршрутам, декоратор
для Flask, встроенная очистка неактивных клиентов.

## Что это

Ограничивает количество запросов от одного клиента (по умолчанию — по IP)
за заданное окно времени. Если лимит превышен — возвращает `429 Too Many
Requests` с заголовками `Retry-After`, `X-RateLimit-Limit`,
`X-RateLimit-Remaining`, `X-RateLimit-Reset`.

### Почему Sliding Window, а не Token Bucket

- Точнее отражает реальную нагрузку — не позволяет делать burst в конце окна
- Не требует настройки отдельного burst-лимита, проще в конфигурации
- Лучше подходит для защиты от брутфорса (равномерное распределение запросов)
- Экономнее по памяти — хранятся только timestamp'ы запросов

## Установка

```bash
git clone https://github.com/m2xdev/rate-limit-shield
cd rate-limit-shield
pip install -r requirements.txt
```

## Использование

### Базовое применение

```python
from flask import Flask
from rate_limit_shield import rate_limit

app = Flask(__name__)

@app.route('/api/data')
@rate_limit(max_requests=100, window_seconds=60)
def get_data():
    return {'data': 'test'}

@app.route('/login', methods=['POST'])
@rate_limit(max_requests=5, window_seconds=60)
def login():
    return {'status': 'ok'}
```

### Готовые строгие лимиты для чувствительных маршрутов

Модуль уже содержит преднастроенные лимиты для типичных «опасных»
маршрутов (`/login`, `/register`, `/api/auth`, `/admin`,
`/reset-password`) — они применяются автоматически через
`RateLimiterFactory`, если не передать свои параметры в декоратор.

### Кастомный обработчик превышения лимита

```python
def custom_429(client_id, route):
    return {'error': 'Slow down'}, 429

@app.route('/api/sensitive')
@rate_limit(max_requests=3, window_seconds=30, on_limit_exceeded=custom_429)
def sensitive_data():
    return {'secret': 'data'}
```

### Периодическая очистка неактивных клиентов

Лимитеры хранят состояние в памяти процесса. Без периодической очистки
память будет расти на каждый новый уникальный IP/route. Вызывай
`cleanup_all()` по расписанию (например, через `APScheduler` или простой
фоновый поток):

```python
from rate_limit_shield import RateLimiterFactory
import threading

def periodic_cleanup():
    RateLimiterFactory.cleanup_all(max_age_seconds=3600)
    threading.Timer(600, periodic_cleanup).start()  # каждые 10 минут

periodic_cleanup()
```

### Статистика

```python
from rate_limit_shield import RateLimiterFactory

stats = RateLimiterFactory.get_stats()
# {'total_limiters': 3, 'total_routes': 3, 'limiters': {...}}
```

## ⚠️ Ограничение для продакшена

`RateLimiter`/`RateLimiterFactory` хранят состояние **в памяти одного
процесса** — это значит:

- Не подходит как есть для приложений с несколькими worker-процессами
  или инстансами (у каждого будет свой независимый счётчик)
- Требует периодической очистки (`cleanup_all()`) на высоконагруженных
  системах, иначе память будет расти
- Для продакшена с реальным трафиком рекомендуется заменить хранилище
  на Redis (общий счётчик между всеми процессами/инстансами)

## Запуск self-test

```bash
python rate_limit_shield.py
```

## ⚠️ Дисклеймер / Disclaimer

### Русская версия

Программное обеспечение предоставляется **«КАК ЕСТЬ»**, без каких-либо
явных или подразумеваемых гарантий. Используя данный код, вы
самостоятельно несёте ответственность за его применение, тестирование
перед использованием в продакшене и любые последствия. Автор не несёт
ответственности за ущерб, возникший в результате использования данного ПО.

### English version

The software is provided **"AS IS"**, without warranty of any kind,
express or implied. By using this code, you are solely responsible for
its use, testing it before production use, and any resulting
consequences. The author is not liable for any damages arising from the
use of this software.

## Связанные проекты

- [xss-shield](https://github.com/m2xdev/xss-shield) / [xss-lab](https://github.com/m2xdev/xss-lab)
- [query-sql](https://github.com/m2xdev/query-sql) / [query-lab](https://github.com/m2xdev/query-lab)
- [csrf-shield](https://github.com/m2xdev/csrf-shield) / [csrf-lab](https://github.com/m2xdev/csrf-lab)
- [mitm-shield](https://github.com/m2xdev/mitm-shield)
- [header-scan](https://github.com/m2xdev/header-scan)