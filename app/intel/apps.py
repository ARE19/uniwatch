"""Domain -> site, application and category, for DNS-based website/app visibility.

`site` is the registrable domain (eTLD+1, e.g. "googlevideo.com"), using tldextract's bundled Public Suffix
List snapshot (no network access). `app` comes from a curated suffix catalogue of widely used services; a
domain not in the catalogue still has a site, just no app name. Matching is by domain suffix on label
boundaries, longest suffix first."""

from functools import lru_cache

import tldextract

_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)   # bundled snapshot only

# category -> {app: [domain suffixes]}
CATALOGUE: dict[str, dict[str, list[str]]] = {
    "Collaboration": {
        "Microsoft Teams": ["teams.microsoft.com", "teams.live.com", "teams.cdn.office.net", "skype.com", "lync.com"],
        "Zoom": ["zoom.us", "zoom.com", "zoomgov.com"],
        "Slack": ["slack.com", "slack-edge.com", "slack-msgs.com"],
        "Webex": ["webex.com", "wbx2.com", "ciscospark.com"],
        "Google Meet": ["meet.google.com"],
    },
    "Microsoft 365": {
        "Outlook / Exchange Online": ["outlook.office365.com", "outlook.office.com", "outlook.live.com", "outlook.com",
                                      "protection.outlook.com", "outlook.cloud.microsoft"],
        "SharePoint / OneDrive": ["spo-msedge.net", "sharepoint.com", "onedrive.com", "onedrive.live.com", "1drv.com", "1drv.ms", "storage.live.com"],
        "Microsoft 365 apps": ["office.com", "office.net", "office365.com", "microsoft365.com", "cloud.microsoft",
                               "officeapps.live.com", "msecnd.net"],
        "Microsoft sign-in": ["login.microsoftonline.com", "login.live.com", "msauth.net", "msftauth.net", "aadcdn.msftauth.net"],
    },
    "Google Workspace": {
        "Gmail": ["mail.google.com", "gmail.com"],
        "Google Drive / Docs": ["drive.google.com", "docs.google.com", "googleusercontent.com", "sheets.google.com"],
        "Google sign-in": ["accounts.google.com"],
    },
    "Search": {
        "Google Search": ["google.com", "google.com.hk", "gstatic.com", "googleapis.com"],
        "Bing": ["bing.com", "bing.net"],
        "Baidu": ["baidu.com", "bdstatic.com"],
    },
    "AI assistants": {
        "ChatGPT / OpenAI": ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"],
        "Claude": ["claude.ai", "anthropic.com"],
        "Microsoft Copilot": ["copilot.microsoft.com", "copilot.cloud.microsoft"],
        "Google Gemini": ["gemini.google.com"],
    },
    "Video streaming": {
        "YouTube": ["youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "youtube-nocookie.com", "youtubei.googleapis.com"],
        "Netflix": ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"],
        "Disney+": ["disneyplus.com", "disney-plus.net", "bamgrid.com", "dssott.com"],
        "Amazon Prime Video": ["primevideo.com", "aiv-cdn.net", "aiv-delivery.net"],
        "Twitch": ["twitch.tv", "ttvnw.net", "jtvnw.net"],
        "Bilibili": ["bilibili.com", "biliapi.net", "hdslb.com"],
        "Viu": ["viu.com", "viu.tv"],
        "TVB": ["tvb.com", "mytvsuper.com"],
    },
    "Music streaming": {
        "Spotify": ["spotify.com", "scdn.co", "spotifycdn.com"],
        "Apple Music": ["music.apple.com"],
        "KKBOX": ["kkbox.com", "kfs.io"],
    },
    "Social media": {
        "Facebook": ["facebook.com", "fbcdn.net", "fb.com", "facebook.net"],
        "Instagram": ["instagram.com", "cdninstagram.com"],
        "TikTok": ["tiktok.com", "tiktokcdn.com", "tiktokv.com", "byteoversea.com", "ibytedtos.com", "musical.ly"],
        "X (Twitter)": ["twitter.com", "x.com", "twimg.com", "t.co"],
        "LinkedIn": ["linkedin.com", "licdn.com"],
        "Reddit": ["reddit.com", "redditmedia.com", "redditstatic.com", "redd.it"],
        "Xiaohongshu": ["xiaohongshu.com", "xhscdn.com"],
        "Weibo": ["weibo.com", "weibo.cn", "sinaimg.cn"],
        "Threads": ["threads.net"],
    },
    "Messaging": {
        "WhatsApp": ["whatsapp.com", "whatsapp.net", "wa.me"],
        "WeChat": ["wechat.com", "weixin.qq.com", "wx.qq.com", "qpic.cn"],
        "Telegram": ["telegram.org", "t.me", "telegram.me"],
        "Signal": ["signal.org", "whispersystems.org"],
        "LINE": ["line.me", "line-apps.com", "line-scdn.net"],
        "Messenger": ["messenger.com"],
    },
    "Cloud storage": {
        "Dropbox": ["dropbox.com", "dropboxapi.com", "dropboxusercontent.com"],
        "iCloud": ["icloud.com", "icloud-content.com"],
        "Box": ["box.com", "boxcdn.net"],
        "WeTransfer": ["wetransfer.com"],
        "Egnyte": ["egnyte.com"],
    },
    "Remote access": {
        "TeamViewer": ["teamviewer.com"],
        "AnyDesk": ["anydesk.com", "net.anydesk.com"],
        "Splashtop": ["splashtop.com"],
        "ScreenConnect": ["screenconnect.com", "connectwise.com"],
    },
    "Gaming": {
        "Steam": ["steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com"],
        "Epic Games": ["epicgames.com", "unrealengine.com"],
        "Xbox": ["xboxlive.com", "xbox.com"],
        "PlayStation": ["playstation.com", "playstation.net", "sonyentertainmentnetwork.com"],
        "Roblox": ["roblox.com", "rbxcdn.com"],
        "Nintendo": ["nintendo.net", "nintendo.com"],
    },
    "Shopping": {
        "Amazon": ["amazon.com", "media-amazon.com", "ssl-images-amazon.com"],
        "Taobao / Alibaba": ["taobao.com", "tmall.com", "alicdn.com", "aliexpress.com", "alibaba.com"],
        "HKTVmall": ["hktvmall.com"],
        "Shopee": ["shopee.com", "shopee.com.hk"],
    },
    "News": {
        "BBC": ["bbc.co.uk", "bbc.com", "bbci.co.uk"],
        "SCMP": ["scmp.com"],
        "CNN": ["cnn.com"],
    },
    "Software updates": {
        "Windows Update": ["windowsupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com", "dl.delivery.mp.microsoft.com"],
        "Apple updates": ["swcdn.apple.com", "mesu.apple.com", "updates.cdn-apple.com"],
        "Ubiquiti": ["ui.com", "ubnt.com", "svc.ui.com"],
    },
    "Security": {
        # Entra Internet/Private Access client: the gateway only sees the tunnel, not the sites inside it.
        "Microsoft Global Secure Access (tunnel)": ["globalsecureaccess.microsoft.com", "ztna1p-msedge.net", "ztna3p-msedge.net"],
        "Microsoft Defender": ["wd.microsoft.com", "smartscreen.microsoft.com", "securitycenter.windows.com"],
        "Huntress": ["huntress.io", "huntress.com"],
    },
    "Advertising & tracking": {
        "Google Ads": ["doubleclick.net", "googlesyndication.com", "googleadservices.com", "googletagmanager.com",
                       "google-analytics.com", "app-measurement.com"],
        "Adobe analytics": ["omtrdc.net", "demdex.net", "sstats.adobe.com"],
        "Telemetry (misc.)": ["bugsnag.com", "newrelic.com", "nr-data.net", "hotjar.com", "mixpanel.com", "scorecardresearch.com"],
    },
    "Apple services": {
        "Apple services": ["apple.com", "mzstatic.com", "aaplimg.com", "apple-dns.net", "cdn-apple.com"],
    },
    "Microsoft services": {
        "Microsoft services": ["microsoft.com", "msn.com", "live.com", "windows.net", "azure.com", "msedge.net",
                               "trafficmanager.net", "azureedge.net"],
    },
}

_SUFFIXES: list[tuple[str, str, str]] = sorted(
    ((sfx, app, cat) for cat, apps in CATALOGUE.items() for app, sfxs in apps.items() for sfx in sfxs),
    key=lambda t: -len(t[0]),
)
APP_CATEGORY = {app: cat for cat, apps in CATALOGUE.items() for app in apps}
LOCAL_SUFFIXES = (".local", ".localdomain", ".lan", ".home", ".internal", ".arpa", ".corp", ".home.arpa")


def is_local(name: str) -> bool:
    return "." not in name or name.endswith(LOCAL_SUFFIXES)


@lru_cache(maxsize=200_000)
def classify(fqdn: str) -> tuple[str | None, str | None, str | None]:
    """'rr3---sn-x.googlevideo.com.' -> ('googlevideo.com', 'YouTube', 'Video streaming'). Local names -> (None, None, None)."""
    name = fqdn.strip().rstrip(".").lower()
    if not name or is_local(name):
        return None, None, None
    ext = _extract(name)
    site = ext.top_domain_under_public_suffix if hasattr(ext, "top_domain_under_public_suffix") else ext.registered_domain
    site = site or name
    for sfx, app, cat in _SUFFIXES:
        if name == sfx or name.endswith("." + sfx):
            return site, app, cat
    return site, None, None
