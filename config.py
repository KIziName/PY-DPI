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
    pending_max_bytes: int = 16384
    pending_timeout_s: float = 2.0
    pending_flush_interval_s: float = 0.5
    block_quic: bool = True


CONFIG = Config()

DEFAULT_DOMAINS = [
    "facebook.com", "fb.com", "fbcdn.net", "fbsbx.com", "messenger.com",
    "facebook.net", "m.me", "fb.gg", "fbwat.ch",
    "instagram.com", "cdninstagram.com", "instagr.am",
    "threads.net", "threads.com", "meta.com",
    "whatsapp.com", "whatsapp.net", "wa.me", "mmg.whatsapp.net",
    "whatsappbrand.com",

    "twitter.com", "x.com", "twimg.com", "t.co",
    "twitter.co", "x.co", "twttr.com", "twttr.net",

    "discord.com", "discordapp.com", "discord.gg", "discordapp.net", "discord.media",
    "discord.co", "discord.new", "discordstatus.com", "discordmerch.com",
    "discordpartners.com", "discord.gift",

    "telegram.org", "telegram.me", "telegram.dog", "telegram.com",
    "t.me", "telegra.ph", "tg.dev",
    "tdesktop.com", "tdesktop.org",
    "web.telegram.org", "core.telegram.org", "api.telegram.org",
    "updates.telegram.org", "edge.telegram.org",
    "cdn-telegram.org", "cdn1-telegram.org", "cdn2-telegram.org",
    "cdn3-telegram.org", "cdn4-telegram.org", "cdn5-telegram.org",
    "venus.web.telegram.org", "pluto.web.telegram.org",
    "flora.web.telegram.org", "vesta.web.telegram.org",
    "aurora.web.telegram.org",
    "kws1.web.telegram.org", "kws2.web.telegram.org",
    "kws3.web.telegram.org", "kws4.web.telegram.org",
    "kws5.web.telegram.org",
    "telesco.pe", "telegram.org.ru",

    "signal.org", "signal.me", "whispersystems.org",
    "signal.art", "signalusers.org", "signal.tube", "signalcdn.com",

    "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com",
    "gstatic.com", "gvt1.com", "gvt2.com", "googleusercontent.com",
    "youtube-nocookie.com", "yt3.ggpht.com",
    "youtube.co", "yt.be", "youtubei.googleapis.com",
    "youtubeeducation.com", "youtubekids.com",
    "ytstatic.com", "youtube.googleapis.com",

    "tiktok.com", "tiktokcdn.com", "tiktokv.com", "muscdn.com",
    "byteoversea.com", "ibytedtos.com", "byteimg.com",
    "tiktokcdn-us.com", "tiktokcdn-eu.com", "ttlivecdn.com",
    "musical.ly", "tiktokmusic.app",

    "reddit.com", "redd.it", "redditstatic.com", "redditmedia.com",
    "redditinc.com", "redditspace.com",
    "reddit.co", "redditblog.com", "reddithelp.com", "reddituploads.com",
    "reddit-stream.com",

    "twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net",
    "twitch.com", "twitchsvc.net", "ext-twitch.tv", "twitch.map.fastly.net",
    "twitch-album.com", "twitchapp.tv", "twitchcon.com",

    "torproject.org", "torproject.net", "tor.eff.org", "tor2web.org",
    "protonvpn.com", "proton.me", "protonmail.com",
    "protonmail.ch", "pm.me", "protonvpn.net",
    "windscribe.com", "windscribe.net",
    "tunnelbear.com", "tunnelbear.net",
    "expressvpn.com", "expressvpn.net",
    "nordvpn.com", "nordvpn.net",
    "surfshark.com", "surfshark.net",
    "cyberghostvpn.com", "cyberghost.net",
    "privateinternetaccess.com", "privateinternetaccess.net",
    "hide.me", "hotspotshield.com", "hotspotshield.net",
    "betternet.co", "psiphon.ca", "psiphon.net",
    "mullvad.net", "mullvad.com",
    "ivpn.net", "airvpn.org", "perfect-privacy.com",
    "amnezia.org", "amneziavpn.com", "getoutline.org", "outline.com",
    "shadowsocks.org", "v2ray.com", "v2fly.org",
    "wireguard.com", "openvpn.net", "zerotier.com", "tailscale.com",
    "hamachi.cc", "logmein.com",

    "cloudflare.com", "cloudflare-dns.com", "cloudflareclient.com",
    "mozilla.cloudflare-dns.com", "one.one.one.one",
    "warp.plus", "cloudflarewarp.com", "cfargotunnel.com",
    "cloudflare-ipfs.com", "cloudflareaccess.com", "cloudflaressl.com",

    "dns.google", "dns.quad9.net",
    "nextdns.io",
    "adguard-dns.io", "dns.adguard.com", "dns-family.adguard.com",
    "doh.opendns.com",
    "doh.dns.sb", "doh.cleanbrowsing.org",
    "dns.mullvad.net",
]
