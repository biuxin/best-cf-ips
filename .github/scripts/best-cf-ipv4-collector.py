import ipaddress
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from curl_cffi import requests as cf_requests

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

try:
    from ip2region import util
    from ip2region.searcher import new_with_buffer
except ImportError:
    util = None
    new_with_buffer = None

if TYPE_CHECKING:
    from ip2region.searcher import Searcher
    from playwright.sync_api import Browser


SOURCES: dict[str, str] = {
    'https://ip.v2too.top/api/nodes': 'You-JP',
    'https://bestcf.pages.dev/tiancheng/hk.txt': 'Tiancheng-HK',
    'https://bestcf.pages.dev/s5gy/hk.txt': 'S5-HK',
    'https://raw.githubusercontent.com/gslege/CloudflareIP/refs/heads/main/SG.txt': 'Gslege-SG',
    'https://raw.githubusercontent.com/gslege/CloudflareIP/refs/heads/main/US.txt': 'Gslege-US',
    'https://raw.githubusercontent.com/ymyuuu/IPDB/refs/heads/main/BestCF/bestcfv4.txt': 'IPDB',
    'https://ip.164746.xyz': 'https://ip.164746.xyz/',
}

PORT: str = '443'
HEADERS: dict[str, str] = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0',
}
IPV4_PATTERN: str = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
OUTPUT_FILE: Path = Path('best-cf-ipv4.txt')
XDB_URL: str = 'https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb'
XDB_FILE: Path = Path(__file__).resolve().parent / 'data' / 'ip2region_v4.xdb'
MAX_RETRIES: int = 3
RETRY_BACKOFF_FACTOR: float = 2.0

# Cloudflare IP段修正映射（基于实际测试和已知PoP位置）
CF_LOCATION_OVERRIDES: dict[str, str] = {
    # 日本东京节点
    '104.16.0.0/12': 'JP',
    '104.20.0.0/14': 'JP',
    '104.26.0.0/15': 'JP',
    '104.28.0.0/14': 'JP',
    '172.64.0.0/13': 'JP',
    '172.68.0.0/14': 'JP',
    
    # 新加坡节点
    '108.156.0.0/14': 'SG',
    '108.160.0.0/13': 'SG',
    
    # 德国法兰克福节点
    '104.24.0.0/15': 'DE',
    '104.27.0.0/16': 'DE',
    
    # 韩国首尔节点
    '104.18.0.0/15': 'KR',
    '104.19.0.0/16': 'KR',
    
    # 澳大利亚悉尼节点
    '104.21.0.0/16': 'AU',
    '104.22.0.0/15': 'AU',
    
    # 美国节点
    '198.41.128.0/17': 'US',
    '198.41.192.0/18': 'US',
    '198.41.240.0/20': 'US',
    
    # 英国伦敦节点
    '104.25.0.0/16': 'GB',
    
    # 加拿大节点
    '104.29.0.0/16': 'CA',
    '104.30.0.0/15': 'CA',
    
    # 香港节点
    '104.23.0.0/16': 'HK',
    '104.31.0.0/16': 'HK',
}

# Cloudflare Anycast IP段特征
CLOUDFLARE_ANYCAST_PREFIXES = ['104.', '108.', '172.6', '198.41.']


def _session() -> cf_requests.Session:
    """Create a session with Chrome TLS fingerprint impersonation."""
    session = cf_requests.Session(impersonate='chrome')
    session.headers.update(HEADERS)
    return session


def fetch(session: cf_requests.Session, url: str, timeout: int = 15) -> str:
    """Fetch a URL with retry support and return response text."""
    last_err: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = session.get(url, timeout=timeout)
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            last_err = e
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BACKOFF_FACTOR ** attempt)
    assert last_err is not None
    raise last_err


def extract_ipv4(text: str) -> set[str]:
    """Extract valid IPv4 addresses from raw text."""
    ips: set[str] = set()
    for match in re.finditer(IPV4_PATTERN, text):
        try:
            ip = ipaddress.ip_address(match.group())
            ips.add(str(ip))
        except ValueError:
            continue
    return ips


def country_to_flag(code: str) -> str:
    if len(code) != 2 or code == 'XX':
        return ''
    return chr(ord(code[0]) - 65 + 0x1F1E6) + chr(ord(code[1]) - 65 + 0x1F1E6)


def _ensure_xdb() -> None:
    """Download the offline xdb database if missing."""
    if XDB_FILE.exists():
        return
    XDB_FILE.parent.mkdir(parents=True, exist_ok=True)
    print(f'Downloading {XDB_URL} ...')
    with _session() as sess:
        resp = sess.get(XDB_URL, timeout=120)
        resp.raise_for_status()
        XDB_FILE.write_bytes(resp.content)


_searcher = None


def _get_searcher() -> 'Searcher':
    """Lazily create a full-memory xdb searcher."""
    global _searcher
    if new_with_buffer is None:
        raise RuntimeError('ip2region not installed; run: pip install ip2region')
    if _searcher is None:
        _ensure_xdb()
        _searcher = new_with_buffer(
            util.version_from_header(util.load_header_from_file(str(XDB_FILE))),
            util.load_content_from_file(str(XDB_FILE)),
        )
    return _searcher


def is_cloudflare_ip(ip: str) -> bool:
    """检查IP是否属于Cloudflare的Anycast范围"""
    return any(ip.startswith(prefix) for prefix in CLOUDFLARE_ANYCAST_PREFIXES)


def get_network_override(ip: str) -> Optional[str]:
    """获取IP所在的Cloudflare网络段"""
    ip_obj = ipaddress.ip_address(ip)
    for network_cidr in CF_LOCATION_OVERRIDES:
        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
            if ip_obj in network:
                return network_cidr
        except ValueError:
            continue
    return None


def lookup_country(ip: str) -> str:
    """
    查询IP地理位置，针对Cloudflare IP进行特殊处理
    1. 如果是Cloudflare IP，优先使用修正映射
    2. 否则使用ip2region离线数据库
    3. 如果都是US，保留US
    """
    # 检查是否在Cloudflare修正映射中
    if is_cloudflare_ip(ip):
        network = get_network_override(ip)
        if network:
            return CF_LOCATION_OVERRIDES[network]
    
    # 使用ip2region查询
    try:
        region = _get_searcher().search(ip)
        # ip2region返回格式: 国家|区域|省份|城市|ISP
        code = region.split('|')[-1].strip()
        if re.fullmatch(r'[A-Z]{2}', code):
            # 如果是Cloudflare IP且识别为US，但可能在修正映射中漏掉了
            if is_cloudflare_ip(ip) and code == 'US':
                # 尝试更详细的IP段匹配
                for network_cidr, country in CF_LOCATION_OVERRIDES.items():
                    try:
                        network = ipaddress.ip_network(network_cidr, strict=False)
                        if ipaddress.ip_address(ip) in network:
                            return country
                    except:
                        continue
            return code
    except Exception:
        pass
    
    # 默认返回US（Cloudflare任何节点都可能是US）
    return 'US'


_browser = None
_pw = None


def _get_browser() -> 'Browser':
    """Lazily start a reusable headless Chromium instance."""
    global _browser, _pw
    if sync_playwright is None:
        raise RuntimeError('playwright not installed; run: pip install playwright && playwright install chromium')
    if _browser is None:
        _pw = sync_playwright().start()
        _browser = _pw.chromium.launch(headless=True)
    return _browser


def fetch_rendered(url: str, timeout: int = 30000) -> str:
    """Render a JS page with headless Chromium and return the final HTML."""
    context = _get_browser().new_context(user_agent=HEADERS['User-Agent'])
    page = context.new_page()
    try:
        page.goto(url, wait_until='networkidle', timeout=timeout)
        return page.content()
    finally:
        context.close()


def collect_ips(session: cf_requests.Session) -> set[str]:
    """Collect IPv4 from all sources, degrading from HTTP to headless browser.

    A source is considered fetched successfully only when it yields at least
    one valid IPv4 address; otherwise the next fetcher tier is tried.
    """
    all_ips: set[str] = set()
    tiers = [
        ('HTTP', lambda u: fetch(session, u)),
        ('Browser', fetch_rendered),
    ]
    for url, name in SOURCES.items():
        for label, fetcher in tiers:
            try:
                ips = extract_ipv4(fetcher(url))
            except Exception as e:
                print(f'  [{name}] {label} failed: {e}')
                continue
            if ips:
                all_ips.update(ips)
                print(f'  [{name}] {label}: {len(ips)} IPv4')
                break
            print(f'  [{name}] {label}: 0 IPv4, trying next tier')
        else:
            print(f'  [{name}] all fetchers failed')
    return all_ips


def enrich_locations(ips: set[str]) -> dict[str, str]:
    """Query geographic locations for all IPs via the offline database with Cloudflare correction."""
    _get_searcher()
    entries: dict[str, str] = {}
    total = len(ips)
    for idx, ip in enumerate(ips, 1):
        country = lookup_country(ip)
        entries[f'{ip}:{PORT}'] = country
        if idx % 100 == 0:
            print(f'  Progress: {idx}/{total}')
    return entries


def main() -> int:
    """Collect Cloudflare IPs, query locations, and write result file."""
    print('Collecting Cloudflare IPs...\n')

    session = _session()

    all_ips = collect_ips(session)
    if not all_ips:
        print('No IPs collected, skip')
        return 1
    print(f'\n{len(all_ips)} unique IPv4')

    print('Querying locations with Cloudflare correction...')
    entries = enrich_locations(all_ips)

    # 统计各地区数量
    country_count = {}
    for location in entries.values():
        country_count[location] = country_count.get(location, 0) + 1
    
    print(f'\nLocation distribution:')
    for country, count in sorted(country_count.items(), key=lambda x: -x[1]):
        flag = country_to_flag(country)
        print(f'  {flag} {country}: {count}')

    tmp = OUTPUT_FILE.with_suffix('.tmp')
    with tmp.open('w', encoding='utf-8') as f:
        for ip_port, location in entries.items():
            f.write(f'{ip_port}#{location} {country_to_flag(location)}\n')
    tmp.replace(OUTPUT_FILE)
    print(f'\n{len(entries)} IPs written to {OUTPUT_FILE}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
