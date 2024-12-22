import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl(url, max_depth=2):
    visited = set()
    to_visit = [(url, 0)]

    while to_visit:
        current_url, depth = to_visit.pop(0)
        if depth > max_depth or current_url in visited:
            continue

        visited.add(current_url)
        try:
            response = requests.get(current_url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(current_url, href)
                if urlparse(full_url).netloc == urlparse(url).netloc:
                    to_visit.append((full_url, depth + 1))
        except requests.RequestException:
            continue

    return visited