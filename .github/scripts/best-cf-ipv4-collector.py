import ipaddress
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from curl_cffi import requests as cf_requests

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

if TYPE_CHECKING:
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
MAX_RETRIES: int = 3
RETRY_BACKOFF_FACTOR: float = 2.0

# IP地理位置API列表（按优先级排序）
IP_API_LIST = [
    {
        'name': 'ip-api.com',
        'url': 'http://ip-api.com/json/{}?fields=countryCode',
        'key': 'countryCode'
    },
    {
        'name': 'ip-api.com(HTTPS)',
        'url': 'https://ip-api.com/json/{}?fields=countryCode',
        'key': 'countryCode'
    },
    {
        'name': 'ipwhois.io',
        'url': 'https://ipwhois.io/json/{}',
        'key': 'country_code'
    },
    {
        'name': 'ipinfo.io',
        'url': 'https://ipinfo.io/{}/json',
        'key': 'country'
    },
]


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


def lookup_country_online(ip: str) -> str:
    """
    使用多个在线API查询IP地理位置
    返回ISO-3166国家代码
    """
    for api in IP_API_LIST:
        try:
            url = api['url'].format(ip)
            with _session() as session:
                resp = session.get(url, timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    country_code = data.get(api['key'], '')
                    
                    # 处理不同API返回的格式
                    if country_code:
                        # 如果返回的是国家全称，转换为代码
                        if len(country_code) > 2:
                            # 尝试从常见名称映射
                            country_map = {
                                'Japan': 'JP',
                                'Singapore': 'SG',
                                'United States': 'US',
                                'Germany': 'DE',
                                'Korea': 'KR',
                                'South Korea': 'KR',
                                'United Kingdom': 'GB',
                                'Hong Kong': 'HK',
                                'China': 'CN',
                                'Taiwan': 'TW',
                                'Australia': 'AU',
                                'Canada': 'CA',
                            }
                            if country_code in country_map:
                                return country_map[country_code]
                            # 如果是英文国家名，取前两个字母的大写
                            if len(country_code) >= 2:
                                code = country_code[:2].upper()
                                if re.fullmatch(r'[A-Z]{2}', code):
                                    return code
                        elif re.fullmatch(r'[A-Z]{2}', country_code):
                            return country_code
        except Exception as e:
            # 如果API失败，尝试下一个
            continue
    
    return 'US'  # 默认返回US


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
    """Query geographic locations for all IPs using online API."""
    entries: dict[str, str] = {}
    total = len(ips)
    print(f'\n查询 {total} 个IP的地理位置...')
    
    # 使用会话复用提高效率
    with _session() as session:
        for idx, ip in enumerate(ips, 1):
            try:
                # 尝试使用在线API查询
                country = lookup_country_online(ip)
                entries[f'{ip}:{PORT}'] = country
                
                # 显示进度
                if idx % 10 == 0:
                    print(f'  进度: {idx}/{total} ({idx*100//total}%)')
                    
            except Exception as e:
                print(f'  查询 {ip} 失败: {e}')
                entries[f'{ip}:{PORT}'] = 'US'
            
            # 避免请求过快
            if idx % 5 == 0:
                time.sleep(0.1)
    
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

    # 测试IP验证
    test_ip = '108.162.198.227'
    test_result = lookup_country_online(test_ip)
    print(f'\nTest IP {test_ip} -> {test_result} {country_to_flag(test_result)}')

    print('\nQuerying locations using online API...')
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
