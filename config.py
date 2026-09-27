from dataclasses import dataclass

APP_TITLE = "PY-DPI"
WINDOW_SIZE = "900x720"
WINDOW_MIN_SIZE = (660, 500)
LOG_POLL_MS = 400
STATS_POLL_MS = 2000
MAX_LOG_LINES = 1000

LOG_FONT = ("Consolas", 9)
DOMAINS_TEXT_HEIGHT = 8
LOG_TEXT_HEIGHT = 14
MODE_COMBO_WIDTH = 12

APP_AUTHOR = "KiziName"
APP_VERSION = "V0.9"
APP_GITHUB = "https://github.com/KIziName/PY-DPI"


MODES = ["split", "disorder", "fake+split", "fake+disorder"]
DEFAULT_MODE = "disorder"

MODES_SPLIT = ["random", "midsld"]
DEFAULT_SPLIT = "midsld"


PORT_HTTP = 80
PORT_HTTPS = 443


FAKE_SNI_BASE = b"www.microsoft.com"
HTTP_METHODS = (
    b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE",
    b"OPTI", b"PATC", b"CONN", b"TRAC", b"PRI ",
)
HTTP_HEADER_MAX_SCAN = 2048

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

IP_WHITELIST_V4 = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
]

IP_WHITELIST_V6 = [
    "::1/128",       
    "::/128",          
    "fc00::/7",     
    "fe80::/10",       
    "ff00::/8",         
]


def build_windivert_filter() -> str:
    return (
        f"(tcp.DstPort == {PORT_HTTPS} or tcp.DstPort == {PORT_HTTP} "
        f"or udp.DstPort == {PORT_HTTPS})"
    )

@dataclass(frozen=True)
class Config:
    disorder_delay_s: float = 0.003
    fake_split_delay_s: float = 0.003
    fake_ttl: int = 1
    fake_repeats: int = 1
    fake_badsum: bool = True
    split_pos: str = DEFAULT_SPLIT
    windivert_filter: str = build_windivert_filter()
    windivert_test_filter: str = "tcp or udp"
    test_duration_s: int = 5
    pending_max_bytes: int = 8192
    pending_timeout_s: float = 2.0
    pending_flush_interval_s: float = 0.5
    block_quic: bool = True


CONFIG = Config()

DEFAULT_DOMAINS = [
    "facebook.com", "fbcdn.net", "fb.com", "fbsbx.com", "fb.watch",
    "messenger.com", "m.me", "facebook.net",
    "instagram.com", "cdninstagram.com",
    "threads.net",
    "whatsapp.com", "whatsapp.net", "wa.me", "whatsapp.org",
    "viber.com", "vb.me", "viber.me", "viber.net", "viber.co",
    "vibercdn.com",
    "twitter.com", "x.com", "twimg.com", "t.co", "x.ai",
    "discord.com", "discordapp.com", "discordapp.net", "discord.gg",
    "discord.media", "discordactivities.com", "discord.co",
    "discord.new", "discord.gift",
    "telegram.org", "t.me", "telegram.me", "telegra.ph",
    "telesco.pe", "cdn-telegram.org", "tg.dev",
    "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com",
    "ggpht.com", "youtubei.googleapis.com", "youtube.googleapis.com",
    "tiktok.com", "tiktokcdn.com", "tiktokv.com", "byteoversea.com",
    "snapchat.com", "snap.com", "sc-cdn.net", "sc-gw.com", "snapkit.com",
    "roblox.com", "rbxcdn.com", "rbx.com", "roblox.org",
    "github.com", "githubusercontent.com", "githubassets.com", "github.io",
    "torproject.org", "torproject.net", "tor.eff.org", "meek.azureedge.net",
    "dns.google", "dns.quad9.net", "dns.nextdns.io",
    "cloudflare-dns.com", "one.one.one.one",
    "dns.adguard.com", "doh.opendns.com",
]
