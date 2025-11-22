#!/usr/bin/env python3
# Recon v0.1 — Stable Core (2025)
# Основная задача: никакие запросы, SSL, ошибки формата, nmap/nuclei не должны ломать выполнение.

import asyncio
import aiohttp
import ssl
import hashlib
import argparse
import logging
import re
import subprocess
import json
import email.utils
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import sys

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# ---------------- LEGAL ----------------
LEGAL = """
=============================================================
LEGAL NOTICE
Инструмент предназначен для аудита только тех ресурсов,
на которые у вас есть разрешение.
=============================================================
"""
print(LEGAL)

# ---------------- Args ----------------
parser = argparse.ArgumentParser()
parser.add_argument("target")
parser.add_argument("--threads", type=int, default=100)
args = parser.parse_args()

target = args.target.lower().strip()
out = Path(f"recon_{target}_{datetime.now():%Y%m%d_%H%M%S}")
out.mkdir(exist_ok=True)

TIMEOUT = aiohttp.ClientTimeout(total=10, connect=4, sock_read=6)

# ---------------- Safe requester ----------------
async def safe_get_json(session, url):
    try:
        async with session.get(url, ssl=False) as r:
            text = await r.text()
            try:
                return json.loads(text)
            except:
                return None
    except:
        return None

async def safe_get_text(session, url):
    try:
        async with session.get(url, ssl=False) as r:
            return await r.text(errors="ignore")
    except:
        return None

# ---------------- Subdomain gather ----------------
async def get_subdomains(session):
    subs = set()

    # FIX: crt.sh больше не принимает "%25." — даёт 403.
    # Рабочий вариант: Identity=%25domain
    crt_url = f"https://crt.sh/?Identity=%25{target}&output=json"

    rapid_url = f"https://rapiddns.io/subdomain/{target}?full=1"

    crt = await safe_get_json(session, crt_url)
    if crt:
        for row in crt:
            ns = str(row.get("name_value", "")).split("\n")
            for n in ns:
                n = n.lower().strip().lstrip("*.") 
                if n.endswith(target):
                    subs.add(n)

    rapid = await safe_get_text(session, rapid_url)
    if rapid:
        for m in re.finditer(r"<td>([\w.-]+)</td>", rapid):
            d = m.group(1).lower()
            if d.endswith(target):
                subs.add(d)

    return subs

# ---------------- SSL safe ----------------
async def get_ssl(host):
    info = {"ok": False, "issuer": "", "expire": ""}
    try:
        ctx = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, 443, ssl=ctx),
            timeout=5
        )
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj:
            cert = ssl_obj.getpeercert()
            issuer = cert.get("issuer", [])
            parsed = [f"{x[0][0]}={x[0][1]}" for x in issuer]
            info["issuer"] = " / ".join(parsed)

            na = cert.get("notAfter", "")
            try:
                dt = email.utils.parsedate_to_datetime(na)
                info["expire"] = dt.isoformat()
            except:
                info["expire"] = na

            info["ok"] = True
        writer.close()
        await writer.wait_closed()
    except:
        pass
    return info

# ---------------- Probe ----------------
async def safe_fetch(session, url):
    try:
        async with session.get(url, ssl=False, allow_redirects=True) as r:
            body = await r.read()
            text = body.decode(errors="ignore") if body else ""
            return r, text
    except:
        return None, ""

async def probe(url, session, sem):
    async with sem:
        resp, text = await safe_fetch(session, url)
        if not resp:
            return None

        title = ""
        m = re.search(r"<title.*?>(.*?)</title>", text, re.I | re.S)
        if m:
            title = m.group(1).strip()

        ssl_info = {}
        if resp.url.scheme == "https":
            try:
                ssl_info = await get_ssl(resp.url.host)
            except:
                ssl_info = {}

        return {
            "url": str(resp.url),
            "status": resp.status,
            "title": title,
            "ssl": ssl_info
        }

# ---------------- Main ----------------
async def main():
    print(f"[+] Запуск Recon v0.1 для: {target}")

    async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
        subs = await get_subdomains(session)
        (out / "subdomains.txt").write_text("\n".join(sorted(subs)))
        print(f"[+] Субдомены: {len(subs)}")

        urls = []
        for s in subs:
            urls.append(f"http://{s}")
            urls.append(f"https://{s}")

        sem = asyncio.Semaphore(args.threads)
        tasks = [probe(u, session, sem) for u in urls]
        results = [r for r in await asyncio.gather(*tasks) if r]

        (out / "results.json").write_text(json.dumps(results, indent=2))

        # HTML report
        html = "<html><body><h1>Recon v0.1</h1><table border=1>"
        html += "<tr><th>Status</th><th>URL</th><th>Title</th></tr>"
        for r in results:
            html += f"<tr><td>{r['status']}</td><td>{r['url']}</td><td>{r['title']}</td></tr>"
        html += "</table></body></html>"
        (out / "report.html").write_text(html)

        print(f"[+] Готово: {out}/report.html")

asyncio.run(main())
