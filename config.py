import struct

from dataclasses import dataclass

# --- Информация о приложении ---
APP_TITLE = "PY-DPI"
APP_AUTHOR = "KiziName"
APP_VERSION = "V1.5"
APP_GITHUB = "https://github.com/KIziName/PY-DPI"

# --- Тексты для окна с ошибкой прав администратора ---
EXIT_NO_ADMIN = 1
ADMIN_REQUIRED_TITLE = APP_TITLE
ADMIN_REQUIRED_MSG = (
    "Требуются права администратора.\n\n"
    "Запусти PY-DPI от имени администратора:\n"
    "  • ПКМ по ярлыку → «Запуск от имени администратора»\n"
    "  • либо из консоли, открытой с повышенными правами."
)

# --- Сетевые порты ---
PORT_HTTP = 80
PORT_HTTPS = 443

# --- HTTP методы для парсинга ---
HTTP_METHODS = (
    b"GET", b"POST", b"HEAD", b"PUT", b"DELETE",
    b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE", b"PRI",
)
_HTTP_METHOD_MAX_LEN = max(len(m) for m in HTTP_METHODS)
HTTP_HEADER_MAX_SCAN = 8192 # Максимальный размер заголовков для чтения

# --- Константы протокола TLS/SSL ---
TLS_CONTENT_HANDSHAKE = 0x16
TLS_HANDSHAKE_CLIENT_HELLO = 0x01
TLS_SNI_EXT_TYPE = 0x0000
TLS_ECH_EXT_TYPE = 0xfe0d         # Encrypted Client Hello
TLS_RECORD_HEADER_LEN = 5
TLS_HANDSHAKE_HEADER_LEN = 4 
TLS_CLIENT_HELLO_VERSION_LEN = 2 
TLS_CLIENT_HELLO_RANDOM_LEN = 32      
TLS_EXT_HEADER_LEN = 4
TLS_MIN_CLIENTHELLO_LEN = 43

# --- Константы для намеренной порчи контрольной суммы (фейк-пакеты) ---
BADSUM_XOR_MIN = 0x0002 
BADSUM_XOR_MAX = 0xFFFE           
BADSUM_FALLBACK = 0x8000            

# --- Константы для расчета статистики ---
BW_WINDOW_S = 2.0 # Окно оценки скорости (в секундах)

_U16 = struct.Struct(">H")

# Быстрый поиск валидных первых байт пакета
_PAYLOAD_FIRST_BYTES = frozenset(
    (TLS_CONTENT_HANDSHAKE,) + tuple(m[0] for m in HTTP_METHODS)
)

# --- Константы TCP Sequence (защита от переполнения) ---
SEQ_MASK = 0xFFFFFFFF
SEQ_HALF = 0x7FFFFFFF

# --- Ограничения TTL для фейков ---
TTL_MIN = 1
TTL_MAX = 6

# --- Разделители и спецсимволы ---
CRLF = b"\r\n"
CRLFCRLF = b"\r\n\r\n"
HOST_HEADER = b"host:"
HOST_PORT_SEP = b":"
DOT_BYTE = 0x2E

# --- Белые списки IP-адресов (локальные сети и служебные диапазоны) ---
IP_WHITELIST_V4 = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
)

IP_WHITELIST_V6 = (
    "::1/128",
    "::/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
)

# --- Доступные режимы обхода и позиции сплита ---
MODES = (
    "split", "disorder", 
    "triple_split", "triple_disorder",
    "fake+split", "fake+disorder"
)
MODES_SPLIT = ("random", "midsld")


@dataclass(frozen=True, slots=True)
class UiConfig:
    """Настройки графического интерфейса (GUI)"""
    window_size: str = "900x720"
    window_min_size: tuple = (660, 500)
    diag_window_size: str = "550x450"
    auto_window_size: str = "500x400"
    dom_window_size: str = "550x650"
    docs_window_size: str = "640x560"

    log_poll_ms: int = 300
    stats_poll_ms: int = 1500
    max_log_lines: int = 500

    log_font: tuple = ("Consolas", 9)
    domains_text_height: int = 8
    log_text_height: int = 14
    mode_combo_width: int = 12

    domains_bg: str = "#f0f0f0"
    link_fg: str = "#0066cc"
    link_fg_hover: str = "#004499"
    about_title_font: tuple = ("Segoe UI", 16, "bold")
    about_link_font: tuple = ("Segoe UI", 9, "underline")

    default_mode: str = "disorder"
    default_split: str = "midsld"


UI = UiConfig()


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    """Настройки многопоточности и таймаутов"""
    shutdown_grace_s: float = 1.0
    stop_watchdog_ms: int = 5000
    close_join_timeout_s: float = 5.0

    packet_queue_maxsize: int = 7000
    worker_join_timeout_s: float = 1.5
    recv_join_timeout_s: float = 1.0
    queue_get_timeout_s: float = 0.2
    queue_put_timeout_s: float = 0.3
    drain_get_timeout_s: float = 0.05
    worker_min_wait_s: float = 0.001
    ip_cache_size: int = 8192


RT = RuntimeConfig()


@dataclass(frozen=True, slots=True)
class DpiConfig:
    """Основные настройки движка обхода DPI"""
    disorder_delay_s: float = 0.005
    fake_split_delay_s: float = 0.003
    fake_ttl: int = 3
    fake_repeats: int = 1
    fake_badsum: bool = True
    split_pos: str = "midsld"

    test_duration_s: int = 5 # Длительность теста WinDivert

    # Настройки буфера для склейки пакетов
    pending_max_bytes: int = 8192
    pending_timeout_s: float = 1.0
    pending_max_packets: int = 32
    pending_flush_interval_s: float = 0.2

    block_quic: bool = True
    fake_sni_tld: bytes = b"com"

    @property
    def windivert_filter(self) -> str:
        """Фильтр пакетов для драйвера WinDivert"""
        return (
            f"(tcp and ((tcp.DstPort == {PORT_HTTPS} or tcp.DstPort == {PORT_HTTP}) "
            f"and tcp.PayloadLength > 0)) "
            f"or (udp and (udp.DstPort == {PORT_HTTPS} and udp.PayloadLength > 0))"
        )

    @property
    def windivert_test_filter(self) -> str:
        """Фильтр для тестового режима"""
        return self.windivert_filter


CONFIG = DpiConfig()

# --- Настройки авто-подбора ---
AUTO_TEST_MODES = [
    "split", 
    "disorder", 
    "triple_split", 
    "triple_disorder", 
    "fake+split", 
    "fake+disorder"
]

AUTO_TEST_HOST = "youtube.com"    # Сайт, на котором тестируем соединение
AUTO_TEST_INIT_DELAY = 2.0        # Секунд на инициализацию WinDivert
AUTO_TEST_SWITCH_DELAY = 0.5      # Секунд на переключение режима
AUTO_TEST_TIMEOUT = 5             # Таймаут подключения 

# --- Цветовые схемы тем ---
THEMES = {
    "Светлая": {
        "bg": "#f0f0f0",
        "fg": "#000000",
        "field_bg": "#ffffff",
        "btn_bg": "#e1e1e1",
        "border": "#cccccc",
        "log_err": "#e74c3c",
        "log_warn": "#f39c12",
        "log_ok": "#2ecc71",
    },
    "Темная": {
        "bg": "#1e1e1e",
        "fg": "#d4d4d4",
        "field_bg": "#2d2d2d",
        "btn_bg": "#333333",
        "border": "#444444",
        "log_err": "#ff6b6b",
        "log_warn": "#feca57",
        "log_ok": "#1dd1a1",
    }
}

# --- Домены для авто-проверки подмены DNS при запуске ---
DNS_CHECK_DOMAINS = (
    "youtube.com",
    "googlevideo.com",
    "instagram.com",
    "facebook.com",
    "x.com",
    "discord.com",
    "telegram.org",
    "tiktok.com",
    "openai.com",
    "github.com",
)

# --- Тексты для окна "Документация" в GUI ---
DOCS_SECTIONS = (
    ("h1", "Что делает PY-DPI"),
    ("p", "Локально обходит DPI-блокировки: разбивает TLS ClientHello "
          "(и HTTP-запросы) на части так, чтобы DPI не распознал "
          "домен, но целевой сервер получил пакет целиком."),

    ("h1", "Режимы"),
    ("h2", "split"),
    ("p", "Разбивает первый пакет соединения на две части и отправляет "
          "их по порядку. Простой и быстрый."),
    ("h2", "disorder"),
    ("p", "Отправляет вторую половину первой, потом первую. DPI видит "
          "некорректный порядок и пропускает, сервер склеивает."),
    ("h2", "fake+split"),
    ("p", "Перед реальным ClientHello отправляет фейковый пакет с "
          "подменённым SNI и низким TTL — DPI его обрабатывает, "
          "а сервер отбрасывает. Затем идёт обычный split."),
    ("h2", "fake+disorder"),
    ("p", "То же, что fake+split, но реальный пакет отправляется "
          "в режиме disorder."),

    ("h2", "triple_split"),
    ("p", "Разрезает пакет на 3 части и отправляет по порядку. "
          "Помогает, если провайдер научился склеивать 2 пакета."),
    ("h2", "triple_disorder"),
    ("p", "Разрезает пакет на 3 части и отправляет в обратном порядке. "
          "Самый мощный метод против умных DPI."),

    ("h1", "Параметры"),
    ("h2", "Split"),
    ("p", "• random — точка разрыва выбирается случайно внутри домена.\n"
          "• midsld — разрыв ровно в середине домена второго уровня."),
    ("h2", "TTL фейка"),
    ("p", "Время жизни фейкового пакета (1–6). Значение должно быть "
          "достаточным, чтобы DPI увидел пакет, но недостаточным, "
          "чтобы он дошёл до сервера."),
    ("h2", "Fake-повторы"),
    ("p", "Сколько раз отправлять фейковый пакет (1–5). Больше — "
          "надёжнее, но заметнее для DPI."),
    ("h2", "Битая сумма фейка"),
    ("p", "Портит контрольную сумму фейкового пакета. Сервер его "
          "отбросит сразу, а DPI всё равно разберёт SNI. Обычно "
          "включено."),
    ("h2", "Обход всего"),
    ("warn", "ВНИМАНИЕ! Обход применяется ко всем соединениям, "
             "а не только к доменам из списка. Может ломать отдельные "
             "сайты и замедлять трафик. Включай осознанно."),

    ("h1", "Кнопки"),
    ("h2", "▶ Старт / ■ Стоп"),
    ("p", "Запускает и останавливает обход. Требуются права "
          "администратора."),
    ("h2", "Сбросить лог"),
    ("p", "Очищает окно лога."),

    ("h2", "🩺 Диагностика"),
    ("p", "Запускает окно всесторонней проверки. Проверяет права администратора, "
          "наличие библиотеки pydivert, подмену DNS, статус брандмауэра Windows, "
          "а также проводит короткий тест перехвата пакетов через WinDivert. "
          "Отличный инструмент, если обход перестал работать."),

    ("h2", "⚡ Авто-подбор"),
    ("p", "Автоматически подбирает самый быстрый и рабочий режим обхода "
          "для вашего провайдера. Программа по очереди запускает все "
          "доступные режимы (split, disorder, triple, fake) и пытается "
          "установить реальное TLS-соединение с YouTube.\n\n"
          "Тест занимает около 15-30 секунд. Победивший режим (тот, что "
          "подключился быстрее всех) автоматически устанавливается в "
          "главном окне программы."),
)

# --- Список доменов, которые обходятся по умолчанию ---
DEFAULT_DOMAINS = (
    # ── Meta ──────────────────────────────────────
    "facebook.com", "fbcdn.net", "fb.com", "fbsbx.com", "fb.watch",
    "messenger.com", "m.me", "facebook.net",
    "instagram.com", "cdninstagram.com", "threads.net",
    "whatsapp.com", "whatsapp.net", "wa.me",

    # ── X / Twitter ───────────────────────────────
    "twitter.com", "x.com", "twimg.com", "t.co",
    "twttr.com", "twttr.net", "twvid.com", "tweetdeck.com",
    "twittercommunity.com", "twitteroauth.com", "twtrdns.net",
    "ads-twitter.com", "cms-twdigitalassets.com",
    "twitter.biz", "twitter.jp", "twitterinc.com", "twitterstat.us",
    "periscope.tv", "pscp.tv", "vine.co", "twitpic.com",
    "tellapart.com", "twitterflightschool.com",

     # ── Discord ───────────────────────────────────
    "discord.com", "discordapp.com", "discordapp.net", "discord.gg",
    "discord.media", "discordactivities.com", "discord.new", "discord.gift",
    "dis.gd", "discord.co", "discord.design", "discord.dev",
    "discord.gifts", "discord.store", "discord.tools",
    "discordmerch.com", "discordpartygames.com",
    "discord-activities.com", "discordsays.com",

    # ── Telegram ──────────────────────────────────
    "telegram.org", "t.me", "telegram.me", "telegra.ph", "telesco.pe",
    "cdn-telegram.org", "telegram-cdn.org", "tdesktop.com",
    "telega.one", "telegram.dog", "telegram.space", "tx.me",
    "fragment.com", "comments.app", "contest.com", "graph.org",
    "quiz.directory", "tg.dev", "usercontent.dev", "ton.org",

    # ── YouTube / Google ──────────────────────────
    "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com",
    "youtubemusic.com", "yt.be", "ggpht.com",
    "youtubei.googleapis.com", "youtube.googleapis.com",
    "youtube-nocookie.com", "youtubekids.com", "googleusercontent.com",
    "gstatic.com", "wide-youtube.l.google.com", "ytimg.l.google.com",
    "youtubeembeddedplayer.googleapis.com", "youtube-ui.l.google.com",
    "yt-video-upload.l.google.com", "jnn-pa.googleapis.com",
    "returnyoutubedislikeapi.com",

    # ── TikTok ────────────────────────────────────
    "tiktok.com", "tiktokcdn.com", "tiktokv.com", "byteoversea.com",
    "ibytedtos.com", "muscdn.com", "musical.ly", "tik-tokapi.com",
    "tiktokcdn-us.com", "tiktokcdn-eu.com", "tiktokd.net", "tiktokd.org",
    "tiktokv.us", "tiktokv.eu", "tiktokw.us", "ttwstatic.com",

    # ── Anime Online (RU) ─────────────────────────
    "jut.su", "jut-su.net", "animego.org", "amedia.site", "yummyani.me",
    "kara.su", "animebest.org", "animedia.tv", "animespirit.ru",
    "sovetromantica.com", "adultmult.tv", "anilibria.tv", "anilibria.uno",
    "anilibria.org", "anilibria.wtf", "anilib.me", "anistars.ru",
    "anistar.org", "animaunt.org", "anime-portal.su", "shiza-project.com",

    # ── Snapchat ──────────────────────────────────
    "snapchat.com", "snap.com", "sc-cdn.net", "sc-gw.com",
    "bitmoji.com", "bitstrips.com", "snapkit.com", "snap-dev.net",
    
    # ── Dev / GitHub ──────────────────────────────
    "github.com", "githubusercontent.com", "githubassets.com",
    "github.io", "githubapp.com", "githubstatus.com", "ghcr.io",

    # ── Tor / Signal ──────────────────────────────
    "torproject.org", "torproject.net", "tor.eff.org",
    "gettor.me", "onion.link", "onion.ws", "onion.pet",
    "meek.azureedge.net",
    "signal.org", "whispersystems.org", "signal.art",
    "signal.group", "signal.me", "signal.tube", "signalcdn.org",
    
    # ── Торренты ──────────────────────────────────
    "rutracker.org", "rutracker.net", "rutracker.ru", "rutracker.cc",
    "rutrk.org", "static.rutracker.org", "api.rutracker.org",
)
