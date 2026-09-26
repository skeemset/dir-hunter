#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dir-hunter: поиск скрытых директорий и файлов для авторизованного багбаунти и пентеста.

Принимает URL цели и словарь, запрашивает каждый путь-кандидат и показывает те,
что выглядят реальными (интересные коды ответа, размеры, отличные от страницы
"не найдено"). Для каждой находки печатает короткую подсказку, что проверить.

Меры безопасности:
  * перед запуском нужно подтвердить, что у вас есть разрешение на тест цели;
  * глобальный лимит скорости и задержка между запросами, чтобы не завалить хост;
  * узнаваемый User-Agent (без маскировки и обхода детекта);
  * калибровка "не найдено" для отсева ложных срабатываний.

Только для Windows, единая точка входа:  python dir-hunter.py https://target.example

Автор: <ваше имя>
Лицензия: MIT
"""

from __future__ import annotations

import argparse
import json
import os
import random
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urljoin, urlparse

# --------------------------------------------------------------------------- #
# Сторонние зависимости. Если их нет, показываем понятное сообщение вместо
# трейсбека: пользователь мог только что склонировать репозиторий.
# --------------------------------------------------------------------------- #
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
except ImportError:  # pragma: no cover - защита окружения
    sys.stderr.write(
        "[!] Нет зависимости 'requests'.\n"
        "    Установите всё командой:  pip install -r requirements.txt\n"
    )
    sys.exit(1)

try:
    import colorama
    from colorama import Fore, Style

    colorama.init(autoreset=True)  # включает ANSI-цвета в консоли Windows
    _COLOR = True
except ImportError:  # цветной вывод не обязателен
    _COLOR = False

    class _Dummy:
        def __getattr__(self, _name):
            return ""

    Fore = Style = _Dummy()  # type: ignore

# Глушим спам InsecureRequestWarning, когда передан --insecure.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERSION = "1.0.0"

# --------------------------------------------------------------------------- #
# Справочные данные: какие коды ответа важны и что значит находка.
# --------------------------------------------------------------------------- #

# Показываются по умолчанию. 404 намеренно отсутствует (это "тут ничего нет").
DEFAULT_STATUS_INCLUDE = {200, 201, 202, 203, 204, 206,
                          301, 302, 307, 308,
                          401, 403, 405, 500, 501, 503}

# Небольшой встроенный список, чтобы инструмент работал, даже если
# wordlists/common.txt удалён. В комплекте идёт список побольше.
FALLBACK_WORDS = [
    "admin", "administrator", "login", "logout", "dashboard", "api", "api/v1",
    "app", "assets", "backup", "backups", "config", "css", "data", "db",
    "debug", "dev", "docs", "download", "downloads", "files", "images", "img",
    "include", "includes", "js", "lib", "log", "logs", "media", "old",
    "private", "public", "scripts", "server-status", "static", "temp", "test",
    "tmp", "upload", "uploads", "user", "users", "vendor", "wp-admin",
    "wp-content", "wp-includes", ".git", ".env", ".svn", "robots.txt",
    "sitemap.xml", ".htaccess", "web.config", "phpinfo.php", "info.php",
    "readme.md", "swagger", "swagger-ui", "graphql", "actuator", "console",
]

# подстрока пути -> (метка, чем интересно)
# Сопоставляется с найденным путём без учёта регистра.
INTERESTING_PATHS = [
    (".git", "Открытые метаданные Git",
     "Попробуйте выкачать репозиторий (git-dumper). Часто в истории лежит весь исходник и секреты."),
    (".svn", "Открытые метаданные SVN",
     "Старые каталоги SVN могут раскрыть исходный код и учётные данные."),
    (".hg", "Открытые метаданные Mercurial",
     "Каталог системы контроля версий открыт, может раскрыть историю исходников."),
    (".env", "Файл окружения",
     "Часто содержит доступы к БД, API-ключи, секретные ключи. Откройте и внимательно прочитайте."),
    ("config", "Путь с конфигом",
     "Ищите строки подключения, ключи и флаги отладки."),
    ("backup", "Бэкап",
     "Бэкапы (.zip/.sql/.tar.gz) часто содержат весь исходник или дампы БД."),
    (".bak", "Резервный файл",
     "Бэкапы редактора или деплоя могут раскрыть исходник рабочего файла."),
    (".old", "Старая копия",
     "Устаревшая копия рабочего файла; сравните её с текущей версией."),
    (".sql", "Дамп SQL",
     "Открыт дамп базы данных, возможны персональные и учётные данные."),
    ("wp-admin", "Админка WordPress",
     "Определите плагины и темы; проверьте слабые пароли и известные CVE."),
    ("wp-content", "Контент WordPress",
     "Пройдитесь по /wp-content/plugins и /themes на предмет уязвимых версий."),
    ("admin", "Админ-поверхность",
     "Точка входа авторизации; проверьте стандартные пароли, обход авторизации и контроль доступа."),
    ("phpinfo", "Вывод phpinfo()",
     "Раскрывает конфигурацию сервера, пути и модули. Отличная разведка, иногда секреты."),
    ("actuator", "Spring Boot Actuator",
     "Проверьте /actuator/env, /heapdump, /mappings; классический источник секретов."),
    ("swagger", "Документация API",
     "Swagger/OpenAPI раскрывает весь API; пройдитесь по всем эндпоинтам."),
    ("graphql", "Эндпоинт GraphQL",
     "Попробуйте интроспекцию, чтобы выгрузить схему, затем ищите дыры в авторизации."),
    ("server-status", "Apache server-status",
     "Может раскрыть текущие URL запросов (включая токены) и внутренние IP."),
    (".ds_store", "Файл .DS_Store",
     "Индекс папки macOS; распарсите его, чтобы узнать скрытые имена файлов."),
    ("id_rsa", "Приватный ключ SSH",
     "Приватный ключ в веб-корне это критичная утечка."),
    ("robots.txt", "robots.txt",
     "Не уязвимость, но записи 'Disallow' это бесплатный список путей для проверки."),
    ("sitemap", "sitemap",
     "Бесплатный список реальных эндпоинтов; используйте их в разведке."),
]


# --------------------------------------------------------------------------- #
# Мелкие помощники
# --------------------------------------------------------------------------- #

def c(text: str, color) -> str:
    """Красит текст, если доступен colorama, иначе возвращает как есть."""
    if not _COLOR:
        return text
    return f"{color}{text}{Style.RESET_ALL}"


def status_color(code: int):
    if 200 <= code < 300:
        return Fore.GREEN
    if 300 <= code < 400:
        return Fore.CYAN
    if code in (401, 403):
        return Fore.YELLOW
    if 400 <= code < 500:
        return Fore.MAGENTA
    return Fore.RED  # 5xx и всё остальное


def _fmt_size(n: int) -> str:
    """Компактный формат размера в байтах для таблицы результатов."""
    if n < 1024:
        return f"{n}B"
    if n < 1024 * 1024:
        return f"{n/1024:.1f}KB"
    return f"{n/1024/1024:.1f}MB"


# --------------------------------------------------------------------------- #
# Лимит скорости: глобальный потокобезопасный троттлинг, общий для всех
# воркеров, чтобы весь скан держался ниже `rate` запросов в секунду
# независимо от числа потоков.
# --------------------------------------------------------------------------- #
class RateLimiter:
    def __init__(self, rate_per_sec: float):
        self.min_interval = (1.0 / rate_per_sec) if rate_per_sec and rate_per_sec > 0 else 0.0
        self._lock = threading.Lock()
        self._next = time.monotonic()

    def acquire(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            scheduled = max(now, self._next)
            self._next = scheduled + self.min_interval
        wait = scheduled - time.monotonic()
        if wait > 0:
            time.sleep(wait)


# --------------------------------------------------------------------------- #
# Модель данных одной находки.
# --------------------------------------------------------------------------- #
@dataclass
class Result:
    url: str
    path: str
    status: int
    size: int
    redirect: str = ""
    words: int = 0
    lines: int = 0

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "path": self.path,
            "status": self.status,
            "size": self.size,
            "redirect": self.redirect,
        }


@dataclass
class Baseline:
    """Что сервер отвечает на путь, которого точно не существует."""
    status: int
    size: int
    is_catch_all: bool  # True, если "случайный" путь вернул 2xx (soft-404 / wildcard)


@dataclass
class Stats:
    sent: int = 0
    errors: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def inc_sent(self):
        with self.lock:
            self.sent += 1

    def inc_error(self):
        with self.lock:
            self.errors += 1


# --------------------------------------------------------------------------- #
# Сканер
# --------------------------------------------------------------------------- #
class DirHunter:
    def __init__(self, args: argparse.Namespace):
        self.base = args.url.rstrip("/") + "/"
        self.args = args
        self.limiter = RateLimiter(args.rate)
        self.stats = Stats()
        self.results: list[Result] = []
        self.results_lock = threading.Lock()
        self.status_include = args.status_include
        self.status_exclude = args.status_exclude
        self.baseline: Baseline | None = None
        self._print_lock = threading.Lock()
        # Строку прогресса рисуем только в реальном терминале; при
        # перенаправлении в файл или пайп анимация \r превращается в мусор.
        self.is_tty = sys.stdout.isatty()

        # Собираем requests.Session с пулом соединений и ограниченными
        # повторами для временных сетевых сбоев (не для долбёжки).
        self.session = requests.Session()
        retry = Retry(
            total=args.retries,
            backoff_factor=0.6,
            status_forcelist=(429, 502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD"]),
            respect_retry_after_header=True,
        )
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=args.threads,
            pool_maxsize=args.threads,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update({"User-Agent": args.user_agent})
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                self.session.headers[k.strip()] = v.strip()
        if args.cookie:
            self.session.headers["Cookie"] = args.cookie
        if args.proxy:
            self.session.proxies = {"http": args.proxy, "https": args.proxy}

    # --- сеть -------------------------------------------------------------- #
    def _request(self, url: str):
        self.limiter.acquire()
        if self.args.delay:
            time.sleep(self.args.delay)
        method = "HEAD" if self.args.head else "GET"
        return self.session.request(
            method,
            url,
            timeout=self.args.timeout,
            allow_redirects=self.args.follow,
            verify=not self.args.insecure,
            stream=False,
        )

    def calibrate(self) -> Baseline:
        """
        Запрашиваем путь, которого не может существовать. Многие серверы
        отвечают 200 с красивой страницей "не найдено" (soft-404) или
        редиректят всё на одну страницу (catch-all). Зная это, мы отсеиваем
        такие ответы из реальных результатов.
        """
        rand = "zzz_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        url = urljoin(self.base, rand)
        try:
            resp = self._request(url)
            size = len(resp.content) if not self.args.head else int(
                resp.headers.get("Content-Length", 0) or 0
            )
            catch_all = 200 <= resp.status_code < 300
            self.baseline = Baseline(status=resp.status_code, size=size, is_catch_all=catch_all)
        except requests.RequestException:
            # Если калибровка не удалась, просто продолжаем без неё.
            self.baseline = Baseline(status=0, size=-1, is_catch_all=False)
        return self.baseline

    def _looks_like_baseline(self, status: int, size: int) -> bool:
        """True, если ответ неотличим от страницы "не найдено"."""
        b = self.baseline
        if not b or not b.is_catch_all:
            return False
        if status != b.status:
            return False
        # Размеры в пределах ~2% (или 32 байт) от эталона считаем той же страницей.
        if b.size < 0:
            return False
        tol = max(32, int(b.size * 0.02))
        return abs(size - b.size) <= tol

    # --- воркер ------------------------------------------------------------ #
    def probe(self, path: str) -> Result | None:
        url = urljoin(self.base, path)
        try:
            resp = self._request(url)
        except requests.RequestException:
            self.stats.inc_error()
            return None
        finally:
            self.stats.inc_sent()

        code = resp.status_code

        # Фильтрация по коду ответа.
        if self.status_exclude and code in self.status_exclude:
            return None
        if self.status_include and code not in self.status_include:
            return None

        body = resp.content if not self.args.head else b""
        size = len(body) if body else int(resp.headers.get("Content-Length", 0) or 0)

        if self._looks_like_baseline(code, size):
            return None  # шум от soft-404 / wildcard

        redirect = resp.headers.get("Location", "") if 300 <= code < 400 else ""
        text = resp.text if body else ""
        result = Result(
            url=url,
            path=path,
            status=code,
            size=size,
            redirect=redirect,
            words=len(text.split()) if text else 0,
            lines=text.count("\n") if text else 0,
        )
        return result

    # --- расширение кандидатов -------------------------------------------- #
    def _candidates(self, words: list[str]) -> list[str]:
        """Превращает слова в конкретные пути, добавляя расширения при необходимости."""
        exts = [e.strip().lstrip(".") for e in self.args.extensions.split(",") if e.strip()] \
            if self.args.extensions else []
        out: list[str] = []
        for w in words:
            w = w.strip().lstrip("/")
            if not w or w.startswith("#"):
                continue
            out.append(w)
            for ext in exts:
                # Не добавляем расширение, если оно уже есть в слове.
                if not w.lower().endswith("." + ext.lower()):
                    out.append(f"{w}.{ext}")
        # Убираем дубли, сохраняя порядок.
        seen = set()
        uniq = []
        for p in out:
            if p not in seen:
                seen.add(p)
                uniq.append(p)
        return uniq

    # --- вывод ------------------------------------------------------------- #
    def _print_result(self, r: Result) -> None:
        arrow = f"  ->  {r.redirect}" if r.redirect else ""
        line = (
            f"{c(str(r.status), status_color(r.status))}  "
            f"{_fmt_size(r.size):>8}  "
            f"/{r.path}{arrow}"
        )
        with self._print_lock:
            if self.is_tty:
                # стираем строку прогресса и печатаем находку над ней
                sys.stdout.write("\r" + " " * 70 + "\r")
            print(line)

    def _print_progress(self, total: int) -> None:
        if not self.is_tty:
            return  # без анимации при перенаправлении или пайпе
        with self._print_lock:
            done = self.stats.sent
            pct = (done / total * 100) if total else 0
            sys.stdout.write(
                f"\r{c('[скан]', Fore.BLUE)} {done}/{total} "
                f"({pct:4.1f}%)  находок={len(self.results)}  ошибок={self.stats.errors}  "
            )
            sys.stdout.flush()

    # --- основной цикл скана ---------------------------------------------- #
    def scan(self, words: list[str]) -> list[Result]:
        candidates = self._candidates(words)
        total = len(candidates)
        print(c(f"[i] путей-кандидатов: {total}, потоков: {self.args.threads}, "
                f"скорость={'без лимита' if not self.args.rate else str(self.args.rate)+'/с'}", Fore.WHITE))
        print()

        with ThreadPoolExecutor(max_workers=self.args.threads) as pool:
            futures = {pool.submit(self.probe, p): p for p in candidates}
            for fut in as_completed(futures):
                r = fut.result()
                if r is not None:
                    with self.results_lock:
                        self.results.append(r)
                    self._print_result(r)
                if self.stats.sent % 5 == 0 or self.stats.sent == total:
                    self._print_progress(total)

        if self.is_tty:
            with self._print_lock:
                sys.stdout.write("\r" + " " * 70 + "\r")
                sys.stdout.flush()
        self.results.sort(key=lambda x: (x.status, x.path))
        return self.results


# --------------------------------------------------------------------------- #
# Движок подсказок: "советы для багбаунти", которые печатаются к каждой находке.
# --------------------------------------------------------------------------- #
def build_hints(results: list[Result]) -> list[str]:
    hints: list[str] = []
    seen_labels: set[str] = set()

    # 1) Подсказки по пути (известные интересные файлы и каталоги).
    for r in results:
        low = r.path.lower()
        for needle, label, tip in INTERESTING_PATHS:
            if needle in low and label not in seen_labels:
                seen_labels.add(label)
                hints.append(f"{c(label, Fore.YELLOW)} на /{r.path}: {tip}")

    # 2) Подсказки по коду ответа.
    n_403 = sum(1 for r in results if r.status == 403)
    n_401 = sum(1 for r in results if r.status == 401)
    n_500 = sum(1 for r in results if 500 <= r.status < 600)
    n_redir = sum(1 for r in results if 300 <= r.status < 400)

    if n_403:
        hints.append(
            f"{c('403 Forbidden', Fore.YELLOW)}, путей: {n_403}. Ресурс СУЩЕСТВУЕТ, но закрыт. "
            "Стоит попробовать обходы 403 (трюки с путём: /admin/., //admin, %2e; "
            "заголовки: X-Original-URL / X-Forwarded-For). "
            "Только на целях, которые вам разрешено тестировать."
        )
    if n_401:
        hints.append(
            f"{c('401 Unauthorized', Fore.YELLOW)}, путей: {n_401}. Требуется авторизация. "
            "Отметьте для тестов с учёткой; проверьте стандартные пароли и слабую авторизацию."
        )
    if n_500:
        hints.append(
            f"{c('5xx ошибки', Fore.RED)}, путей: {n_500}. Серверные ошибки могут раскрывать "
            "стектрейсы и внутренние пути, иногда намекают на точки инъекций."
        )
    if n_redir:
        hints.append(
            f"{c('Редиректы', Fore.CYAN)}, путей: {n_redir}. Проверьте цели в Location; "
            "тут часто всплывают открытые редиректы и скрытые формы входа."
        )

    # 3) Общая подсказка по методологии.
    if any(r.path.lower() == "robots.txt" for r in results):
        hints.append("robots.txt найден: прочитайте список Disallow; эти пути бесплатные цели.")

    return hints


# --------------------------------------------------------------------------- #
# Вывод в файл
# --------------------------------------------------------------------------- #
def save_output(path: str, target: str, results: list[Result], hints_plain: list[str]) -> None:
    _, ext = os.path.splitext(path.lower())
    if ext == ".json":
        payload = {
            "target": target,
            "generated": datetime.now().isoformat(timespec="seconds"),
            "tool": f"dir-hunter {VERSION}",
            "count": len(results),
            "results": [r.to_dict() for r in results],
            "hints": hints_plain,
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
    else:  # обычный текст
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"# отчёт dir-hunter {VERSION}\n")
            fh.write(f"# цель: {target}\n")
            fh.write(f"# создан: {datetime.now().isoformat(timespec='seconds')}\n\n")
            for r in results:
                extra = f"  -> {r.redirect}" if r.redirect else ""
                fh.write(f"{r.status}\t{r.size}\t/{r.path}{extra}\n")
            if hints_plain:
                fh.write("\n# Подсказки\n")
                for h in hints_plain:
                    fh.write(f"- {h}\n")


def strip_ansi(s: str) -> str:
    """Убирает коды цвета, чтобы вывод в файл был чистым."""
    import re
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


# --------------------------------------------------------------------------- #
# Подтверждение авторизации: вы подтверждаете, что вам можно тестировать цель.
# --------------------------------------------------------------------------- #
def authorisation_gate(target: str, assume_yes: bool) -> bool:
    host = urlparse(target).netloc or target
    print(c("=" * 68, Fore.WHITE))
    print(c(" ТОЛЬКО ДЛЯ ЗАКОННОГО И ЭТИЧНОГО ИСПОЛЬЗОВАНИЯ",
            Fore.RED + Style.BRIGHT if _COLOR else None))
    print(c("=" * 68, Fore.WHITE))
    print(
        "dir-hunter шлёт автоматические запросы к цели. Запускайте только против\n"
        "систем, которыми вы владеете или которые вам явно разрешено тестировать\n"
        f"(например, актив в скоупе багбаунти). Несанкционированное сканирование\n"
        f"может быть незаконным.\n\n"
        f"  Цель: {c(host, Fore.CYAN)}\n"
    )
    if assume_yes:
        print(c("[авторизовано через --yes]", Fore.GREEN))
        return True
    try:
        ans = input("Введите 'yes', чтобы подтвердить разрешение на тест этой цели: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return ans in ("y", "yes", "да", "д")


# --------------------------------------------------------------------------- #
# Словарь
# --------------------------------------------------------------------------- #
def load_wordlist(path: str | None) -> list[str]:
    # Явно указанный путь в приоритете.
    if path:
        if not os.path.isfile(path):
            sys.stderr.write(f"[!] Словарь не найден: {path}\n")
            sys.exit(1)
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]

    # По умолчанию: wordlists/common.txt рядом со скриптом.
    here = os.path.dirname(os.path.abspath(__file__))
    default = os.path.join(here, "wordlists", "common.txt")
    if os.path.isfile(default):
        with open(default, "r", encoding="utf-8", errors="ignore") as fh:
            words = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        if words:
            return words

    print(c("[!] Файл словаря не найден; использую небольшой встроенный список.", Fore.YELLOW))
    return list(FALLBACK_WORDS)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
BANNER = r"""
      _ _        _                 _
   __| (_)_ __  | |__  _   _ _ __ | |_ ___ _ __
  / _` | | '__| | '_ \| | | | '_ \| __/ _ \ '__|
 | (_| | | |    | | | | |_| | | | | ||  __/ |
  \__,_|_|_|    |_| |_|\__,_|_| |_|\__\___|_|
"""


def parse_status_set(value: str | None) -> set[int]:
    if not value:
        return set()
    out: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.add(int(part))
        except ValueError:
            sys.stderr.write(f"[!] Пропускаю неверный код ответа: {part}\n")
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dir-hunter.py",
        description="Поиск скрытых директорий и файлов для авторизованного багбаунти и пентеста.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "примеры:\n"
            "  python dir-hunter.py https://target.example\n"
            "  python dir-hunter.py https://target.example -w wordlists/common.txt -x php,bak\n"
            "  python dir-hunter.py https://target.example -t 20 --rate 30 -o report.json\n"
            "  python dir-hunter.py https://target.example --proxy http://127.0.0.1:8080  # через Burp\n"
        ),
    )
    p.add_argument("url", nargs="?", help="базовый URL цели, напр. https://target.example")
    p.add_argument("-w", "--wordlist", help="путь к словарю (по умолчанию: wordlists/common.txt)")
    p.add_argument("-x", "--extensions", default="",
                   help="расширения через запятую для каждого слова, напр. php,html,bak")
    p.add_argument("-t", "--threads", type=int, default=10, help="число потоков (по умолчанию 10)")
    p.add_argument("--rate", type=float, default=0.0,
                   help="глобальный лимит запросов в секунду на все потоки (0 = без лимита)")
    p.add_argument("--delay", type=float, default=0.0,
                   help="доп. задержка между запросами в секундах (вежливость)")
    p.add_argument("--timeout", type=float, default=10.0, help="таймаут запроса в секундах")
    p.add_argument("--retries", type=int, default=2, help="повторы при временных ошибках (по умолчанию 2)")
    p.add_argument("--head", action="store_true", help="использовать HEAD вместо GET (быстрее, без тела)")
    p.add_argument("--follow", action="store_true", help="переходить по редиректам (по умолчанию нет)")
    p.add_argument("-o", "--output", help="сохранить результаты в файл (.json или .txt по расширению)")
    p.add_argument("--status-include", type=parse_status_set, default=None,
                   help="показывать только эти коды ответа, напр. 200,301,403")
    p.add_argument("--status-exclude", type=parse_status_set, default=None,
                   help="никогда не показывать эти коды, напр. 404,400")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="доп. заголовок 'Имя: значение' (можно несколько раз)")
    p.add_argument("--cookie", help="значение заголовка Cookie для сканов с авторизацией")
    p.add_argument("--proxy", help="пускать трафик через прокси, напр. http://127.0.0.1:8080")
    p.add_argument("-A", "--user-agent",
                   default=f"dir-hunter/{VERSION} (+authorised-testing)",
                   help="свой User-Agent")
    p.add_argument("-k", "--insecure", action="store_true", help="не проверять TLS-сертификат")
    p.add_argument("-y", "--yes", action="store_true",
                   help="пропустить интерактивное подтверждение (вы всё равно подтверждаете авторизацию)")
    p.add_argument("--no-hints", action="store_true", help="не печатать подсказки для багбаунти")
    p.add_argument("--no-banner", action="store_true", help="не показывать ASCII-баннер")
    p.add_argument("--version", action="version", version=f"dir-hunter {VERSION}")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.no_banner:
        print(c(BANNER, Fore.CYAN))
        print(c(f"  dir-hunter {VERSION} - поиск контента для авторизованного тестирования\n", Fore.WHITE))

    if not args.url:
        parser.print_help()
        return 1

    # Нормализуем URL: если схема не указана, ставим https://.
    if not urlparse(args.url).scheme:
        args.url = "https://" + args.url

    # Определяем фильтры кодов (пустой набор от пользователя уважаем, а
    # "не задано" заменяем набором по умолчанию).
    if args.status_include is None:
        args.status_include = set(DEFAULT_STATUS_INCLUDE)
    if args.status_exclude is None:
        args.status_exclude = set()

    if args.threads < 1:
        args.threads = 1

    if not authorisation_gate(args.url, args.yes):
        print(c("[x] Не подтверждено. Отмена.", Fore.RED))
        return 2

    words = load_wordlist(args.wordlist)

    hunter = DirHunter(args)

    # Проверка связи и калибровка.
    print(c("\n[i] Калибровка по случайному пути для выявления soft-404...", Fore.WHITE))
    base = hunter.calibrate()
    if base.status == 0:
        print(c("[!] Не удалось связаться с целью во время калибровки.", Fore.RED))
        print(c("    Проверьте URL, схему (http:// или https://) и сеть.\n"
                "    Подсказка: без схемы инструмент по умолчанию использует https://.", Fore.YELLOW))
        return 1
    elif base.is_catch_all:
        print(c(f"[!] Цель отвечает {base.status} на несуществующие пути "
                f"(размер ~{_fmt_size(base.size)}). Фильтр wildcard/soft-404 ВКЛЮЧЁН.", Fore.YELLOW))
    else:
        print(c(f"[i] Эталон для несуществующих путей: HTTP {base.status}. Ок.", Fore.GREEN))

    start = time.time()
    try:
        results = hunter.scan(words)
    except KeyboardInterrupt:
        print(c("\n[!] Прервано. Показываю, что успели найти.\n", Fore.YELLOW))
        results = sorted(hunter.results, key=lambda x: (x.status, x.path))
    elapsed = time.time() - start

    # --- итог ------------------------------------------------------------- #
    print()
    print(c("=" * 68, Fore.WHITE))
    print(c(f"[+] Готово за {elapsed:.1f}с. запросов: {hunter.stats.sent}, "
            f"находок: {len(results)}, ошибок: {hunter.stats.errors}.", Fore.GREEN))
    print(c("=" * 68, Fore.WHITE))

    if not results:
        print(c("[i] Интересных путей не найдено. Попробуйте словарь побольше (-w) "
                "или расширения (-x php,html,txt).", Fore.WHITE))

    # --- подсказки -------------------------------------------------------- #
    hints = build_hints(results)
    if hints and not args.no_hints:
        print()
        print(c("ПОДСКАЗКИ (куда смотреть дальше):",
                Fore.MAGENTA + Style.BRIGHT if _COLOR else None))
        for h in hints:
            print("  " + c("*", Fore.MAGENTA) + " " + h)

    # --- сохранение ------------------------------------------------------- #
    if args.output:
        hints_plain = [strip_ansi(h) for h in hints]
        try:
            save_output(args.output, args.url, results, hints_plain)
            print(c(f"\n[+] Сохранено в {args.output}", Fore.GREEN))
        except OSError as exc:
            print(c(f"\n[!] Не удалось записать {args.output}: {exc}", Fore.RED))

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[x] Прервано.")
        sys.exit(130)
