#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
rate_limit_shield.py - Защита от DDoS/брутфорса через rate limiting
======================================================================

Модуль предоставляет:
- Класс RateLimiter с алгоритмом скользящего окна (Sliding Window)
- Декоратор @rate_limit для Flask-маршрутов
- Конфигурируемые лимиты для разных endpoints
- Логирование превышений лимитов

Алгоритм: Sliding Window
------------------------
Выбран вместо Token Bucket, т.к.:
1. Точнее отражает реальную нагрузку — не позволяет делать burst в конце окна
2. Не требует настройки burst-лимита, проще в конфигурации
3. Лучше защищает от брутфорса (равномерное распределение запросов)
4. Меньше потребляет памяти (храним только timestamp'ы запросов)

⚠️ ВАЖНОЕ ОГРАНИЧЕНИЕ ДЛЯ ПРОДАКШЕНА:
----------------------------------------
RateLimiterFactory и RateLimiter хранят состояние в памяти процесса
без ограничения роста — _instances и storage растут на каждый новый
route/client_id соответственно и никогда не очищаются автоматически.

Не предназначено для продакшена с высоким трафиком без периодической
очистки (например, задачи по расписанию, вызывающей reset() для
неактивных клиентов) или замены на внешнее хранилище (Redis и т.п.).

Для высоконагруженных систем рекомендуется:
- Использовать Redis в качестве бэкенда хранения
- Добавить периодическую очистку неактивных клиентов (cleanup)
- Ограничить максимальное количество хранимых клиентов

Лицензия: MIT
Copyright (c) 2024

ДАННЫЙ ПРОГРАММНЫЙ ПРОДУКТ ПРЕДОСТАВЛЯЕТСЯ "КАК ЕСТЬ",
БЕЗ КАКИХ-ЛИБО ГАРАНТИЙ, ЯВНЫХ ИЛИ ПОДРАЗУМЕВАЕМЫХ.
"""

import sys  # FIXED: добавлен импорт sys
import time
import logging
from collections import defaultdict, deque
from functools import wraps
from typing import Dict, Optional, Callable, Any, Tuple
from datetime import datetime, timedelta

try:
    from flask import request, jsonify, current_app
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


# ============================================================
# 1. КОНФИГУРАЦИЯ
# ============================================================

class RateLimitConfig:
    """Конфигурация лимитов по умолчанию"""
    
    # Стандартные лимиты
    DEFAULT_MAX_REQUESTS = 100
    DEFAULT_WINDOW_SECONDS = 60
    
    # Строгие лимиты для чувствительных маршрутов
    STRICT_MAX_REQUESTS = 10
    STRICT_WINDOW_SECONDS = 60
    
    # Лимиты по умолчанию для разных маршрутов
    ROUTE_LIMITS = {
        '/login': (STRICT_MAX_REQUESTS, STRICT_WINDOW_SECONDS),
        '/register': (STRICT_MAX_REQUESTS, STRICT_WINDOW_SECONDS),
        '/api/auth': (STRICT_MAX_REQUESTS, STRICT_WINDOW_SECONDS),
        '/admin': (STRICT_MAX_REQUESTS, STRICT_WINDOW_SECONDS),
        '/reset-password': (5, 300),  # 5 запросов за 5 минут
    }
    
    # Заголовки для ответа 429
    RETRY_AFTER_HEADER = 'Retry-After'
    
    # Максимальное количество клиентов в памяти (предупреждение)
    MAX_CLIENTS_WARNING = 10000


# ============================================================
# 2. ЛОГГИРОВАНИЕ
# ============================================================

# NullHandler по умолчанию (без спама в консоль)
logger = logging.getLogger('rate_limit_shield')
logger.addHandler(logging.NullHandler())

# Настройка для self-test (только для тестов)
_test_logger = logging.getLogger('rate_limit_shield_test')
_test_logger.addHandler(logging.NullHandler())


# ============================================================
# 3. ОСНОВНОЙ КЛАСС RATE LIMITER
# ============================================================

class RateLimiter:
    """
    Rate Limiter с алгоритмом Sliding Window.
    
    Алгоритм:
    - Хранит timestamp'ы каждого запроса в deque
    - При проверке удаляет записи старше window_seconds
    - Если количество оставшихся записей >= max_requests — блокирует
    
    Преимущества:
    - Точное отслеживание нагрузки в реальном времени
    - Равномерное распределение запросов
    - Защита от burst-атак в конце окна
    
    Атрибуты:
        max_requests (int): Максимальное количество запросов за окно
        window_seconds (int): Длительность окна в секундах
        storage (Dict[str, deque]): Хранилище timestamp'ов по client_id
        _lock: Блокировка для потокобезопасности
    """
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        """
        Инициализация RateLimiter.
        
        Args:
            max_requests: Максимальное количество запросов за окно
            window_seconds: Длительность окна в секундах
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.storage: Dict[str, deque] = defaultdict(deque)
        self._lock = None  # Для потокобезопасности (опционально)
        
        # Импортируем threading только если нужно
        try:
            import threading
            self._lock = threading.RLock()
        except ImportError:
            pass
    
    def is_allowed(self, client_id: str) -> bool:
        """
        Проверяет, разрешен ли запрос для данного клиента.
        
        Args:
            client_id: Идентификатор клиента (IP, user_id, и т.д.)
            
        Returns:
            bool: True если запрос разрешен, False если лимит превышен
            
        Example:
            >>> limiter = RateLimiter(max_requests=3, window_seconds=10)
            >>> limiter.is_allowed('192.168.1.1')
            True
            >>> limiter.is_allowed('192.168.1.1')  # 2-й запрос
            True
            >>> limiter.is_allowed('192.168.1.1')  # 3-й запрос
            True
            >>> limiter.is_allowed('192.168.1.1')  # 4-й запрос (блокировка)
            False
        """
        now = time.time()
        
        # Используем блокировку для потокобезопасности
        if self._lock:
            with self._lock:
                return self._check_and_add(client_id, now)
        else:
            return self._check_and_add(client_id, now)
    
    def _check_and_add(self, client_id: str, now: float) -> bool:
        """
        Внутренний метод проверки и добавления запроса.
        
        Args:
            client_id: Идентификатор клиента
            now: Текущее время в секундах
            
        Returns:
            bool: True если запрос разрешен
        """
        # Получаем или создаем deque для клиента
        timestamps = self.storage[client_id]
        
        # Удаляем записи старше окна
        cutoff = now - self.window_seconds
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()
        
        # Проверяем лимит
        if len(timestamps) >= self.max_requests:
            return False
        
        # Добавляем текущий запрос
        timestamps.append(now)
        return True
    
    def get_current_count(self, client_id: str) -> int:
        """
        Возвращает текущее количество запросов в окне для клиента.
        
        Args:
            client_id: Идентификатор клиента
            
        Returns:
            int: Количество запросов в текущем окне
        """
        now = time.time()
        cutoff = now - self.window_seconds
        
        if self._lock:
            with self._lock:
                timestamps = self.storage.get(client_id)
                if not timestamps:
                    return 0
                
                # Очищаем старые записи
                while timestamps and timestamps[0] < cutoff:
                    timestamps.popleft()
                
                return len(timestamps)
        else:
            timestamps = self.storage.get(client_id)
            if not timestamps:
                return 0
            
            while timestamps and timestamps[0] < cutoff:
                timestamps.popleft()
            
            return len(timestamps)
    
    def reset(self, client_id: Optional[str] = None):
        """
        Сбрасывает лимиты для клиента или для всех клиентов.
        
        Args:
            client_id: Если указан, сбрасывает только для этого клиента.
                      Если None, сбрасывает для всех.
        """
        if self._lock:
            with self._lock:
                if client_id:
                    self.storage.pop(client_id, None)
                else:
                    self.storage.clear()
        else:
            if client_id:
                self.storage.pop(client_id, None)
            else:
                self.storage.clear()
    
    def get_remaining(self, client_id: str) -> int:
        """
        Возвращает количество оставшихся разрешенных запросов.
        
        Args:
            client_id: Идентификатор клиента
            
        Returns:
            int: Оставшееся количество запросов в окне
        """
        current = self.get_current_count(client_id)
        return max(0, self.max_requests - current)
    
    def get_reset_time(self, client_id: str) -> Optional[float]:
        """
        Возвращает время сброса окна для клиента.
        
        Args:
            client_id: Идентификатор клиента
            
        Returns:
            Optional[float]: Timestamp сброса или None если записей нет
        """
        if self._lock:
            with self._lock:
                timestamps = self.storage.get(client_id)
                if not timestamps:
                    return None
                return timestamps[0] + self.window_seconds
        else:
            timestamps = self.storage.get(client_id)
            if not timestamps:
                return None
            return timestamps[0] + self.window_seconds
    
    def cleanup_stale_clients(self, max_age_seconds: int = 3600):
        """
        Очищает клиентов, которые не активны дольше max_age_seconds.
        
        Args:
            max_age_seconds: Максимальный возраст неактивности в секундах
        """
        now = time.time()
        cutoff = now - max_age_seconds
        
        if self._lock:
            with self._lock:
                stale_clients = []
                for client_id, timestamps in self.storage.items():
                    # Проверяем последний timestamp
                    if timestamps and timestamps[-1] < cutoff:
                        stale_clients.append(client_id)
                
                for client_id in stale_clients:
                    del self.storage[client_id]
                
                return len(stale_clients)
        else:
            stale_clients = []
            for client_id, timestamps in self.storage.items():
                if timestamps and timestamps[-1] < cutoff:
                    stale_clients.append(client_id)
            
            for client_id in stale_clients:
                del self.storage[client_id]
            
            return len(stale_clients)


# ============================================================
# 4. ФАБРИКА ДЛЯ СОЗДАНИЯ ЛИМИТЕРОВ (FIXED)
# ============================================================

class RateLimiterFactory:
    """
    Фабрика для создания и управления RateLimiter'ами.
    
    Позволяет создавать лимитеры с разными конфигурациями для разных маршрутов.
    
    ⚠️ ВАЖНО: Хранит состояние в памяти без ограничения роста.
    Для продакшена с высоким трафиком требуется периодическая очистка
    или замена на внешнее хранилище (Redis).
    """
    
    _instances: Dict[str, RateLimiter] = {}
    _default_limiter: Optional[RateLimiter] = None
    _route_configs: Dict[str, Tuple[int, int]] = {}  # route -> (max_req, window)
    
    @classmethod
    def get_limiter(cls, route: str = None, 
                   max_requests: int = None, 
                   window_seconds: int = None) -> RateLimiter:
        """
        Возвращает RateLimiter для маршрута.
        
        FIXED: Лимитер создается и переиспользуется строго по ключу route.
        Явные max_requests/window_seconds влияют на то, С КАКИМИ лимитами
        создается лимитер при первом обращении, а не создают параллельный
        отдельный лимитер.
        
        Args:
            route: Путь маршрута (например, '/login')
            max_requests: Максимальное количество запросов (переопределяет конфиг)
            window_seconds: Длительность окна (переопределяет конфиг)
            
        Returns:
            RateLimiter: Экземпляр лимитера
        """
        if not route:
            # Возвращаем дефолтный лимитер
            if cls._default_limiter is None:
                cls._default_limiter = RateLimiter(
                    RateLimitConfig.DEFAULT_MAX_REQUESTS,
                    RateLimitConfig.DEFAULT_WINDOW_SECONDS
                )
            return cls._default_limiter
        
        # Определяем лимиты для маршрута
        if max_requests is not None and window_seconds is not None:
            # Используем явно переданные параметры
            limits = (max_requests, window_seconds)
        elif route in cls._route_configs:
            # Используем ранее сохраненную конфигурацию
            limits = cls._route_configs[route]
        else:
            # Ищем в глобальном конфиге
            for pattern, (max_req, window) in RateLimitConfig.ROUTE_LIMITS.items():
                if route.startswith(pattern) or route == pattern:
                    limits = (max_req, window)
                    break
            else:
                # Используем дефолтные
                limits = (RateLimitConfig.DEFAULT_MAX_REQUESTS,
                         RateLimitConfig.DEFAULT_WINDOW_SECONDS)
        
        # Сохраняем конфигурацию для маршрута
        cls._route_configs[route] = limits
        
        # Создаем или переиспользуем лимитер для маршрута
        if route not in cls._instances:
            cls._instances[route] = RateLimiter(limits[0], limits[1])
        
        return cls._instances[route]
    
    @classmethod
    def reset_all(cls):
        """Сбрасывает все лимитеры"""
        for limiter in cls._instances.values():
            limiter.reset()
        cls._instances.clear()
        cls._route_configs.clear()
        if cls._default_limiter:
            cls._default_limiter.reset()
            cls._default_limiter = None
    
    @classmethod
    def cleanup_all(cls, max_age_seconds: int = 3600):
        """
        Очищает неактивных клиентов во всех лимитерах.
        
        Args:
            max_age_seconds: Максимальный возраст неактивности в секундах
        """
        total_cleaned = 0
        for limiter in cls._instances.values():
            total_cleaned += limiter.cleanup_stale_clients(max_age_seconds)
        
        if cls._default_limiter:
            total_cleaned += cls._default_limiter.cleanup_stale_clients(max_age_seconds)
        
        return total_cleaned
    
    @classmethod
    def get_stats(cls) -> Dict[str, Any]:
        """
        Возвращает статистику по всем лимитерам.
        """
        stats = {
            'total_limiters': len(cls._instances),
            'total_routes': len(cls._route_configs),
            'limiters': {}
        }
        
        for route, limiter in cls._instances.items():
            stats['limiters'][route] = {
                'max_requests': limiter.max_requests,
                'window_seconds': limiter.window_seconds,
                'active_clients': len(limiter.storage),
                'total_clients_ever': sum(len(v) for v in limiter.storage.values())
            }
        
        return stats


# ============================================================
# 5. ДЕКОРАТОР ДЛЯ FLASK
# ============================================================

def rate_limit(
    max_requests: int = None,
    window_seconds: int = None,
    route_limits: Dict[str, Tuple[int, int]] = None,
    client_id_func: Callable = None,
    on_limit_exceeded: Callable = None
):
    """
    Декоратор для ограничения частоты запросов к Flask-маршрутам.
    
    Args:
        max_requests: Максимальное количество запросов за окно
        window_seconds: Длительность окна в секундах
        route_limits: Словарь с кастомными лимитами для маршрутов
        client_id_func: Функция для получения client_id (по умолчанию IP)
        on_limit_exceeded: Функция-обработчик при превышении лимита
        
    Returns:
        Декоратор для view-функции
    
    Example:
        @app.route('/login', methods=['POST'])
        @rate_limit(max_requests=5, window_seconds=60)
        def login():
            return {'status': 'ok'}
        
        @app.route('/api/data')
        @rate_limit(route_limits={'/api/data': (10, 30)})
        def get_data():
            return {'data': []}
    """
    if not FLASK_AVAILABLE:
        raise ImportError(
            "Flask не установлен. Установите: pip install flask"
        )
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Определяем client_id
            if client_id_func:
                client_id = client_id_func()
            else:
                # По умолчанию используем IP адрес
                client_id = request.remote_addr or 'unknown'
            
            # Определяем маршрут
            route = request.path
            
            # Получаем лимитер
            if route_limits and route in route_limits:
                max_req, window = route_limits[route]
                limiter = RateLimiterFactory.get_limiter(route, max_req, window)
            elif max_requests is not None and window_seconds is not None:
                limiter = RateLimiterFactory.get_limiter(route, max_requests, window_seconds)
            else:
                limiter = RateLimiterFactory.get_limiter(route)
            
            # Проверяем лимит
            if not limiter.is_allowed(client_id):
                # Логируем нарушение
                current_count = limiter.get_current_count(client_id)
                logger.warning(
                    f"Rate limit exceeded: client={client_id}, "
                    f"route={route}, count={current_count}, "
                    f"limit={limiter.max_requests}/{limiter.window_seconds}s"
                )
                
                # Вызываем кастомный обработчик если есть
                if on_limit_exceeded:
                    return on_limit_exceeded(client_id, route)
                
                # Возвращаем 429 Too Many Requests
                # FIXED: убран client_id из ответа
                retry_after = limiter.window_seconds
                remaining = limiter.get_remaining(client_id)
                response = jsonify({
                    'error': 'Too Many Requests',
                    'message': f'Rate limit exceeded. Limit: {limiter.max_requests} requests per {limiter.window_seconds} seconds.',
                    'retry_after': retry_after,
                    'remaining': remaining
                })
                response.status_code = 429
                response.headers[RateLimitConfig.RETRY_AFTER_HEADER] = str(retry_after)
                
                # Добавляем заголовки для информирования клиента
                response.headers['X-RateLimit-Limit'] = str(limiter.max_requests)
                response.headers['X-RateLimit-Remaining'] = str(remaining)
                reset_time = limiter.get_reset_time(client_id)
                if reset_time:
                    response.headers['X-RateLimit-Reset'] = str(int(reset_time))
                
                return response
            
            # Запрос разрешен - добавляем заголовки
            remaining = limiter.get_remaining(client_id)
            reset_time = limiter.get_reset_time(client_id)
            
            # Выполняем view-функцию
            result = func(*args, **kwargs)
            
            # Если результат - кортеж с ответом и статусом
            if isinstance(result, tuple) and len(result) == 2:
                response, status = result
                if hasattr(response, 'headers'):
                    response.headers['X-RateLimit-Limit'] = str(limiter.max_requests)
                    response.headers['X-RateLimit-Remaining'] = str(remaining)
                    if reset_time:
                        response.headers['X-RateLimit-Reset'] = str(int(reset_time))
                return result
            
            return result
        
        return wrapper
    
    return decorator


# ============================================================
# 6. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================

def get_client_ip() -> str:
    """
    Получает реальный IP клиента с учетом прокси.
    
    Returns:
        str: IP адрес клиента
    """
    if not FLASK_AVAILABLE:
        return 'unknown'
    
    # Проверяем заголовки прокси
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip
    
    return request.remote_addr or 'unknown'


# ============================================================
# 7. SELF-TEST
# ============================================================

def _test_rate_limiter():
    """Self-test для RateLimiter"""
    print("\n[TEST] Testing RateLimiter...")
    
    # Тест 1: Базовое ограничение
    limiter = RateLimiter(max_requests=3, window_seconds=10)
    client_id = 'test_client_1'
    
    # Первые 3 запроса должны быть разрешены
    for i in range(3):
        assert limiter.is_allowed(client_id), f"Запрос {i+1} должен быть разрешен"
    
    # 4-й запрос должен быть заблокирован
    assert not limiter.is_allowed(client_id), "4-й запрос должен быть заблокирован"
    
    print("✓ Тест 1 пройден: базовое ограничение работает")
    
    # Тест 2: Разные client_id
    limiter = RateLimiter(max_requests=2, window_seconds=10)
    client1 = 'client_1'
    client2 = 'client_2'
    
    assert limiter.is_allowed(client1), "Клиент 1: запрос 1 разрешен"
    assert limiter.is_allowed(client1), "Клиент 1: запрос 2 разрешен"
    assert not limiter.is_allowed(client1), "Клиент 1: запрос 3 заблокирован"
    
    assert limiter.is_allowed(client2), "Клиент 2: запрос 1 разрешен"
    assert limiter.is_allowed(client2), "Клиент 2: запрос 2 разрешен"
    assert not limiter.is_allowed(client2), "Клиент 2: запрос 3 заблокирован"
    
    print("✓ Тест 2 пройден: разные client_id считаются независимо")
    
    # Тест 3: Сброс после истечения окна
    limiter = RateLimiter(max_requests=1, window_seconds=2)
    client = 'test_client_3'
    
    assert limiter.is_allowed(client), "Первый запрос разрешен"
    assert not limiter.is_allowed(client), "Второй запрос заблокирован"
    
    # Ждем истечения окна
    time.sleep(2.1)
    
    assert limiter.is_allowed(client), "После истечения окна запрос разрешен"
    
    print("✓ Тест 3 пройден: сброс после истечения окна работает")
    
    # Тест 4: get_current_count и get_remaining
    limiter = RateLimiter(max_requests=5, window_seconds=10)
    client = 'test_client_4'
    
    assert limiter.get_current_count(client) == 0, "Начальный счетчик = 0"
    assert limiter.get_remaining(client) == 5, "Осталось 5 запросов"
    
    for i in range(3):
        limiter.is_allowed(client)
    
    assert limiter.get_current_count(client) == 3, "Счетчик = 3"
    assert limiter.get_remaining(client) == 2, "Осталось 2 запроса"
    
    print("✓ Тест 4 пройден: get_current_count и get_remaining работают")
    
    # Тест 5: reset
    limiter = RateLimiter(max_requests=2, window_seconds=10)
    client = 'test_client_5'
    
    limiter.is_allowed(client)
    limiter.is_allowed(client)
    assert not limiter.is_allowed(client), "Третий запрос заблокирован"
    
    limiter.reset(client)
    assert limiter.is_allowed(client), "После reset запрос разрешен"
    
    print("✓ Тест 5 пройден: reset работает")
    
    # Тест 6: Factory (FIXED: проверка переиспользования)
    # Очищаем фабрику перед тестом
    RateLimiterFactory.reset_all()
    
    # Первый вызов с явными параметрами
    limiter1 = RateLimiterFactory.get_limiter('/login', max_requests=5, window_seconds=30)
    
    # Второй вызов без параметров — должен вернуть ТОТ ЖЕ лимитер
    limiter2 = RateLimiterFactory.get_limiter('/login')
    
    # Третий вызов с другими параметрами — должен вернуть ТОТ ЖЕ лимитер
    limiter3 = RateLimiterFactory.get_limiter('/login', max_requests=10, window_seconds=60)
    
    # Все три должны быть одним и тем же объектом
    assert limiter1 is limiter2, "Factory должен переиспользовать лимитер для одного маршрута"
    assert limiter1 is limiter3, "Factory должен переиспользовать лимитер для одного маршрута"
    
    # Проверяем, что лимиты сохранились с первого вызова
    assert limiter1.max_requests == 5, "Лимиты должны сохраниться с первого вызова"
    assert limiter1.window_seconds == 30, "Лимиты должны сохраниться с первого вызова"
    
    # Проверяем, что разные маршруты имеют разные лимитеры
    limiter4 = RateLimiterFactory.get_limiter('/api/data')
    assert limiter1 is not limiter4, "Разные маршруты должны иметь разные лимитеры"
    
    print("✓ Тест 6 пройден: Factory переиспользует лимитеры корректно")
    
    # Тест 7: Кастомные лимиты из конфига
    # Создаем новый маршрут, которого нет в конфиге
    limiter = RateLimiterFactory.get_limiter('/custom')
    assert limiter.max_requests == RateLimitConfig.DEFAULT_MAX_REQUESTS
    assert limiter.window_seconds == RateLimitConfig.DEFAULT_WINDOW_SECONDS
    
    print("✓ Тест 7 пройден: кастомные лимиты из конфига работают")
    
    # Тест 8: cleanup_stale_clients
    limiter = RateLimiter(max_requests=10, window_seconds=60)
    client = 'test_client_8'
    
    limiter.is_allowed(client)
    time.sleep(0.1)
    
    # Очищаем клиентов старше 0.05 секунд
    cleaned = limiter.cleanup_stale_clients(max_age_seconds=0.05)
    assert cleaned >= 1, "cleanup_stale_clients должен удалять неактивных клиентов"
    
    # Проверяем, что клиент удален
    assert limiter.get_current_count(client) == 0, "Клиент должен быть удален"
    
    print("✓ Тест 8 пройден: cleanup_stale_clients работает")
    
    print("\n[SUCCESS] Все self-tests пройдены!\n")
    return True


def _test_imports():
    """Проверяет наличие необходимых импортов"""
    required_imports = [
        'sys', 'time', 'logging', 'collections', 'functools', 'typing', 'datetime'
    ]
    
    for module in required_imports:
        try:
            __import__(module)
        except ImportError:
            print(f"[FAIL] Модуль {module} не найден")
            return False
    
    return True


def self_test() -> bool:
    """
    Запускает все self-tests.
    
    Returns:
        bool: True если все тесты пройдены
    """
    print("\n" + "="*50)
    print("  RATE_LIMIT_SHIELD - SELF-TEST")
    print("="*50)
    
    # Проверка импортов
    if not _test_imports():
        print("[FAIL] Self-test не пройден: отсутствуют необходимые модули")
        return False
    
    try:
        # Тестируем RateLimiter
        _test_rate_limiter()
        
        print("\n[OK] Все self-tests успешно пройдены!")
        return True
        
    except AssertionError as e:
        print(f"\n[FAIL] Self-test не пройден: {e}")
        import traceback
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"\n[ERROR] Self-test завершился с ошибкой: {e}")
        import traceback
        traceback.print_exc()
        return False


# ============================================================
# 8. ПРИМЕР ИСПОЛЬЗОВАНИЯ
# ============================================================

def example_usage():
    """
    Пример использования RateLimiter в Flask-приложении.
    """
    if not FLASK_AVAILABLE:
        print("[!] Flask не установлен. Пропускаем пример.")
        return
    
    # from flask import Flask, request
    # app = Flask(__name__)
    
    # # Простой лимит
    # @app.route('/api/data')
    # @rate_limit(max_requests=100, window_seconds=60)
    # def get_data():
    #     return {'data': 'test'}
    
    # # Строгий лимит для логина
    # @app.route('/login', methods=['POST'])
    # @rate_limit(max_requests=5, window_seconds=60)
    # def login():
    #     return {'status': 'ok'}
    
    # # Кастомный обработчик превышения
    # def custom_429(client_id, route):
    #     return {'error': 'Too many requests', 'client': client_id}, 429
    
    # @app.route('/api/sensitive')
    # @rate_limit(
    #     max_requests=3,
    #     window_seconds=30,
    #     on_limit_exceeded=custom_429
    # )
    # def sensitive_data():
    #     return {'secret': 'data'}
    
    print("[+] Пример использования:")
    print("    from rate_limit_shield import rate_limit, RateLimiterFactory")
    print("    from flask import Flask")
    print("    app = Flask(__name__)")
    print()
    print("    @app.route('/api/data')")
    print("    @rate_limit(max_requests=100, window_seconds=60)")
    print("    def get_data():")
    print("        return {'data': 'test'}")
    print()
    print("    @app.route('/login', methods=['POST'])")
    print("    @rate_limit(max_requests=5, window_seconds=60)")
    print("    def login():")
    print("        return {'status': 'ok'}")
    print()
    print("    # Периодическая очистка (задача по расписанию)")
    print("    # RateLimiterFactory.cleanup_all(max_age_seconds=3600)")
    print()
    print("    if __name__ == '__main__':")
    print("        app.run()")


# ============================================================
# 9. ТОЧКА ВХОДА
# ============================================================

if __name__ == '__main__':
    # Запускаем self-test
    success = self_test()
    
    if success:
        print("\n[OK] rate_limit_shield.py готов к использованию!")
        example_usage()
    else:
        print("\n[FAIL] rate_limit_shield.py не прошел self-test.")
        sys.exit(1)