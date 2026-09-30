from dataclasses import dataclass

APP_TITLE = "PY-DPI"
APP_AUTHOR = "KiziName"
APP_VERSION = "V1.0"
APP_GITHUB = "https://github.com/KIziName/PY-DPI"

EXIT_NO_ADMIN = 1
ADMIN_REQUIRED_TITLE = APP_TITLE
ADMIN_REQUIRED_MSG = (
    "Требуются права администратора.\n\n"
    "Запусти PY-DPI от имени администратора:\n"
    "  • ПКМ по ярлыку → «Запуск от имени администратора»\n"
    "  • либо из консоли, открытой с повышенными правами."
)

PORT_HTTP = 80
PORT_HTTPS = 443

FAKE_SNI_BASE = b"www.microsoft.com"
HTTP_METHODS = (
    b"GET", b"POST", b"HEAD", b"PUT", b"DELETE",
    b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE", b"PRI",
)
HTTP_HEADER_MAX_SCAN = 4096

TLS_CONTENT_HANDSHAKE = 0x16
TLS_HANDSHAKE_CLIENT_HELLO = 0x01
TLS_SNI_EXT_TYPE = 0x0000
TLS_RECORD_HEADER_LEN = 5
TLS_EXT_HEADER_LEN = 4
TLS_MIN_CLIENTHELLO_LEN = 43

SEQ_MASK = 0xFFFFFFFF
SEQ_HALF = 0x7FFFFFFF

CHECKSUM_MASK = 0xFFFF
CHECKSUM_FLIP = 0x0001

TTL_MIN = 1
TTL_MAX = 12

CRLF = b"\r\n"
CRLFCRLF = b"\r\n\r\n"
HOST_HEADER = b"host:"
HOST_PORT_SEP = b":"

DOT_BYTE = 0x2E

IP_WHITELIST_V4 = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
)

IP_WHITELIST_V6 = (
    "::1/128",
    "::/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
)

MODES = ("split", "disorder", "fake+split", "fake+disorder")
MODES_SPLIT = ("random", "midsld")


@dataclass(frozen=True)
class UiConfig:
    window_size: str = "900x720"
    window_min_size: tuple = (660, 500)

    log_poll_ms: int = 600
    stats_poll_ms: int = 2000
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


@dataclass(frozen=True)
class RuntimeConfig:
    shutdown_grace_s: float = 1.0
    stop_watchdog_ms: int = 5000
    close_join_timeout_s: float = 3.0

    packet_queue_maxsize: int = 5000
    worker_join_timeout_s: float = 1.5
    recv_join_timeout_s: float = 1.0
    queue_get_timeout_s: float = 0.2
    queue_put_timeout_s: float = 0.3
    drain_get_timeout_s: float = 0.05
    worker_max_wait_s: float = 0.1
    worker_min_wait_s: float = 0.001
    ip_cache_size: int = 8192


RT = RuntimeConfig()


@dataclass(frozen=True)
class DpiConfig:
    disorder_delay_s: float = 0.005
    fake_split_delay_s: float = 0.005
    fake_ttl: int = 1
    fake_repeats: int = 1
    fake_badsum: bool = True
    split_pos: str = "midsld"

    test_duration_s: int = 5

    pending_max_bytes: int = 8192
    pending_timeout_s: float = 1.0
    pending_max_packets: int = 32
    pending_flush_interval_s: float = 0.2

    block_quic: bool = True

    @property
    def windivert_filter(self) -> str:
        return (
            f"((tcp.DstPort == {PORT_HTTPS} or tcp.DstPort == {PORT_HTTP}) "
            f"and tcp.PayloadLength > 0) "
            f"or (udp.DstPort == {PORT_HTTPS} and udp.PayloadLength > 0)"
        )

    @property
    def windivert_test_filter(self) -> str:
        return self.windivert_filter


CONFIG = DpiConfig()

DEFAULT_DOMAINS = (
    "facebook.com", "fbcdn.net", "fb.com", "fbsbx.com", "fb.watch",
    "messenger.com", "m.me", "facebook.net",
    "instagram.com", "cdninstagram.com", "threads.net",
    "whatsapp.com", "whatsapp.net", "wa.me", "whatsapp.org",
    "viber.com", "vb.me", "viber.me", "viber.net", "viber.co",
    "vibercdn.com", "twitter.com", "x.com", "twimg.com", "t.co", "x.ai",
    "discord.com", "discordapp.com", "discordapp.net", "discord.gg",
    "discord.media", "discordactivities.com", "discord.new", "discord.gift",
    "telegram.org", "t.me", "telegram.me", "telegra.ph", "telesco.pe", "cdn-telegram.org",
    "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "youtubemusic.com", "yt.be",
    "ggpht.com", "youtubei.googleapis.com", "youtube.googleapis.com", "youtube-nocookie.com", "youtubekids.com",
    "tiktok.com", "tiktokcdn.com", "tiktokv.com", "byteoversea.com",
    "snapchat.com", "snap.com", "sc-cdn.net", "sc-gw.com",
    "github.com", "githubusercontent.com", "githubassets.com",
    "torproject.org", "torproject.net", "tor.eff.org",
    "dns.google", "dns.quad9.net", "dns.nextdns.io", "cloudflare-dns.com", "one.one.one.one",
    "dns.adguard.com", "doh.opendns.com", "openai.com", "chatgpt.com", "oaiusercontent.com", "oaistatic.com",
    "signal.org", "whispersystems.org",
    "soundcloud.com", "sndcdn.com",
)
