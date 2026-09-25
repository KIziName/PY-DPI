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


@dataclass(frozen=True)
class Config:
    disorder_delay_s: float = 0.003
    fake_split_delay_s: float = 0.003
    fake_ttl: int = 1
    fake_repeats: int = 1
    fake_badsum: bool = True
    split_pos: str = DEFAULT_SPLIT
    windivert_filter: str = (
        f"(tcp.DstPort == {PORT_HTTPS} or tcp.DstPort == {PORT_HTTP} "
        f"or udp.DstPort == {PORT_HTTPS})"
    )
    windivert_test_filter: str = "tcp or udp"
    test_duration_s: int = 5
    pending_max_bytes: int = 8192
    pending_timeout_s: float = 2.0
    pending_flush_interval_s: float = 0.5
    block_quic: bool = True


CONFIG = Config()

DEFAULT_DOMAINS = [
    "facebook.com", "fb.com", "fbcdn.net", "fbsbx.com", "messenger.com",
    "instagram.com", "cdninstagram.com", "threads.net", "threads.com",

    "whatsapp.com", "whatsapp.net", "wa.me",

    "twitter.com", "x.com", "twimg.com", "t.co",

    "discord.com", "discordapp.com", "discord.gg",

    "telegram.org", "telegram.me", "telegram.dog",
    "t.me", "telegra.ph", "tg.dev", "telesco.pe",

    "signal.org", "signal.me", "whispersystems.org",

    "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com",
    "ggpht.com", "youtubei.googleapis.com", "youtube.googleapis.com",

    "tiktok.com", "tiktokcdn.com", "tiktokv.com", "byteoversea.com",

    "reddit.com", "redd.it", "redditstatic.com", "redditmedia.com",

    "twitch.tv", "ttvnw.net", "jtvnw.net",

    "torproject.org", "torproject.net",

    "dns.google", "dns.quad9.net",
    "nextdns.io", "dns.nextdns.io",
    "adguard-dns.io", "dns.adguard.com",
    "doh.opendns.com", "doh.dns.sb",
    "dns.mullvad.net", "mullvad.net",

    "protonvpn.com", "protonvpn.net", "proton.me", "protonmail.com",
    "nordvpn.com", "nordvpn.net",
    "expressvpn.com", "expressvpn.net",
    "surfshark.com", "surfshark.net",
    "windscribe.com", "windscribe.net",
    "tunnelbear.com", "tunnelbear.net",
    "mullvad.com",
    "ivpn.net",
    "amnezia.org", "amneziavpn.com",
    "getoutline.org",
]