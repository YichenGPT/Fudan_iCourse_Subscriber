"""Human-approved QR authentication in the same GitHub runner session.

Only authenticated ciphertext is published. School tokens/cookies stay in RAM.
Protocol follows the school's ac/js/chunk-71ba4ca7.61b64444.js second-login UI.
"""
import base64
import hashlib
import io
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor

from PIL import Image
import requests
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256


def school_qr_png(value):
    """qrMsg is an image source in the school's UI, not QR payload text."""
    if not isinstance(value, str) or not value.startswith("data:image/"):
        raise PermissionError("学校返回了不支持的二维码图片格式，请检查扫码接口")
    header, encoded = value.split(",", 1)
    if ";base64" not in header or len(encoded) > 4_000_000:
        raise PermissionError("二维码图片格式或大小不正确")
    try:
        raw = base64.b64decode(encoded, validate=True)
        with Image.open(io.BytesIO(raw)) as image:
            if image.width * image.height > 4_000_000:
                raise ValueError("image too large")
            output = io.BytesIO()
            image.convert("RGB").save(output, format="PNG")
            return output.getvalue()
    except (ValueError, OSError) as exc:
        raise PermissionError("学校二维码图片无法解码") from exc


def seal(payload, student, password, run):
    salt, nonce = os.urandom(16), os.urandom(12)
    secret = hashlib.sha256(f"ICS-QR-v1:{student}:{password}".encode()).digest()
    key = PBKDF2(secret, salt, 32, count=200000, hmac_hash_module=SHA256)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(run.encode())
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(payload).encode())
    return {"version": 1, "run": run, **{k: base64.b64encode(v).decode()
            for k, v in dict(salt=salt, nonce=nonce, ciphertext=ciphertext, tag=tag).items()}}


def authenticate_browser(vpn, student, password):
    """Let the official school UI own QR generation, confirmation and redirects.

    Browser state is ephemeral. Only the encrypted QR image leaves the runner;
    cookies are imported into the existing downloader only after a user API probe.
    """
    from playwright.sync_api import sync_playwright, Error
    from urllib.parse import quote, urlparse
    from src.api.webvpn import get_vpn_url
    from src.runtime import config

    box = Mailbox()
    link = f"https://{box.repo.split('/')[0]}.github.io/{box.repo.split('/')[1]}/auth.html?run={box.run}"
    print(f"[学校网页验证，最多15分钟] {link}", flush=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as stream:
            stream.write(f"\n## 学校官方网页验证\n[打开本次扫码入口]({link})\n\n确认后自动验证 iCourse 会话并继续处理课程。\n")
    cas = get_vpn_url(
        f"{config.ICOURSE_BASE}/casapi/index.php?r=auth/login&school_login=1"
        f"&tenant_code={config.TENANT_CODE}&forward={quote(config.ICOURSE_BASE + '/', safe='')}"
    )
    proxy_host = urlparse(config.WEBVPN_BASE).hostname
    latest = {"png": None, "invalid": False, "generation": 0}
    outcome = "expired"

    def observe(response):
        try:
            path = urlparse(response.url).path
            if path.endswith("/authn/getAuthQr"):
                data = response.json()
                if str(data.get("code")) == "200":
                    latest.update(png=school_qr_png(data["data"]["qrMsg"]), invalid=False,
                                  generation=latest["generation"] + 1)
            elif path.endswith("/authn/authExecute"):
                data = response.json()
                code = str(data.get("code"))
                print(f"[学校网页返回] code={code}; second={bool(data.get('second'))}; token_present={bool(data.get('loginToken'))}", flush=True)
                if code == "4005":
                    latest["invalid"] = True
        except (ValueError, KeyError, PermissionError, Error):
            # Navigation can cancel a response body. The page remains authoritative.
            pass

    def import_cookies(context):
        vpn.session.cookies.clear()
        for cookie in context.cookies():
            if cookie["domain"].lstrip(".") == proxy_host:
                vpn.session.cookies.set(cookie["name"], cookie["value"],
                    domain=cookie["domain"], path=cookie["path"], secure=cookie["secure"])

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 1200, "height": 900})
            page = context.new_page()
            page.on("response", observe)
            try:
                page.goto(cas, wait_until="domcontentloaded", timeout=60000)
            except Error:
                print("[学校网页] 正在等待学校登录页面加载。", flush=True)
            deadline = time.monotonic() + 900
            published = -1
            last_probe = last_refresh = last_notice = last_route = 0
            password_pages = set()
            while time.monotonic() < deadline:
                page.wait_for_timeout(1000)
                now = time.monotonic()
                current = urlparse(page.url)
                if now - last_probe > 8:
                    last_probe = now
                    import_cookies(context)
                    vpn.session.headers["User-Agent"] = page.evaluate("navigator.userAgent")
                    try:
                        response = vpn.get(config.ICOURSE_BASE + "/userapi/v1/infosimple", timeout=8)
                        data = response.json()
                        user_info = data.get("params") or data.get("data") or {}
                        if (response.status_code == 200 and data.get("code") in (0, 200)
                                and isinstance(user_info, dict) and user_info.get("id")):
                            vpn.logged_in = True
                            outcome = "verified"
                            print("[学校网页] iCourse 用户接口验证成功，继续抓课和总结。", flush=True)
                            return True
                    except (requests.RequestException, ValueError):
                        pass
                if latest["png"] and published != latest["generation"] and not latest["invalid"]:
                    box.publish({"state": "waiting", "expires": int(time.time()) + 90,
                                 "png": base64.b64encode(latest["png"]).decode()}, student, password)
                    published = latest["generation"]
                    print("[学校网页] 已同步官方页面二维码，请用微信扫码确认。", flush=True)
                if latest["invalid"] and now - last_refresh > 5:
                    last_refresh = now
                    box.publish({"state": "waiting", "expires": int(time.time()), "png": ""}, student, password)
                    refresh = page.locator(".qrcode-refresh").filter(visible=True)
                    if refresh.count():
                        refresh.first.click(timeout=3000)
                    else:
                        candidate = page.get_by_text("刷新", exact=True).filter(visible=True)
                        if candidate.count():
                            candidate.first.click(timeout=3000)
                # Complete the existing password step only on official school origins.
                if current.hostname in (proxy_host, urlparse(config.IDP_BASE).hostname):
                    pwd = page.locator('input[type="password"]:visible')
                    if pwd.count() and page.url not in password_pages and not latest["png"]:
                        user = page.locator('input[placeholder*="学工号"]:visible, input[placeholder*="用户名"]:visible')
                        if not user.count():
                            user = page.locator('input[type="text"]:visible')
                        submit = page.get_by_text("登录", exact=True).filter(visible=True)
                        if user.count() and submit.count():
                            user.first.fill(student)
                            pwd.first.fill(password)
                            password_pages.add(page.url)
                            submit.first.click(timeout=5000)
                            print("[学校网页] 已提交学校登录，等待官方后续认证。", flush=True)
                if (current.hostname == proxy_host and current.path in ("/", "/portal", "/portal/")
                        and now - last_route > 20):
                    last_route = now
                    page.goto(cas, wait_until="domcontentloaded", timeout=30000)
                if now - last_notice > 30:
                    last_notice = now
                    print(f"[学校网页] 等待验证，剩余 {int(deadline-now)} 秒；阶段={'二维码' if latest['png'] else '加载登录页面'}。", flush=True)
            raise PermissionError("学校网页验证等待已满15分钟；已有课程数据保留")
    finally:
        try:
            box.publish({"state": outcome, "expires": int(time.time()), "png": ""}, student, password)
        except requests.RequestException:
            pass


class Mailbox:
    def __init__(self):
        self.repo = os.environ["GITHUB_REPOSITORY"]
        self.run = os.environ["GITHUB_RUN_ID"] + "-" + os.environ.get("GITHUB_RUN_ATTEMPT", "1")
        self.api = requests.Session()
        self.api.headers.update({"Authorization": "Bearer " + os.environ["GITHUB_TOKEN"],
                                 "Accept": "application/vnd.github+json"})
        self.base = "https://api.github.com/repos/" + self.repo
        response = self.api.get(self.base + "/git/ref/heads/auth", timeout=30)
        if response.status_code == 404:
            result = self.api.post(self.base + "/git/refs", json={
                "ref": "refs/heads/auth", "sha": os.environ["GITHUB_SHA"]}, timeout=30)
            if result.status_code != 422:
                result.raise_for_status()
        else:
            response.raise_for_status()

    def publish(self, payload, student, password):
        url = self.base + "/contents/auth/" + self.run + ".json"
        old = self.api.get(url, params={"ref": "auth"}, timeout=30)
        body = {"branch": "auth", "message": "auth: update encrypted scan session",
                "content": base64.b64encode(json.dumps(seal(payload, student, password, self.run)).encode()).decode()}
        if old.status_code == 200:
            body["sha"] = old.json()["sha"]
        elif old.status_code != 404:
            old.raise_for_status()
        self.api.put(url, json=body, timeout=30).raise_for_status()


def authenticate(vpn, challenge, original, headers, student, password):
    from src.api.webvpn import get_vpn_url
    from src.runtime import config
    if "qr" not in challenge.get("moduleCodes", []):
        raise PermissionError("学校未向此会话提供扫码认证")
    box = Mailbox()
    link = f"https://{box.repo.split('/')[0]}.github.io/{box.repo.split('/')[1]}/auth.html?run={box.run}"
    print(f"[等待扫码，最多15分钟] {link}", flush=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as stream:
            stream.write(f"\n## 等待学校扫码验证\n[打开扫码入口]({link})\n\n最多等待15分钟；用课程页面的学号和密码在浏览器本地解密二维码。\n")
    deadline = time.monotonic() + 900
    outcome = "expired"
    public = requests.Session()
    public.headers.update({"Referer": config.IDP_BASE + "/ac/", "Origin": config.IDP_BASE})
    direct = False
    try:
        while time.monotonic() < deadline:
            transport = public if direct else vpn.session
            endpoint = lambda path: config.IDP_BASE + "/idp/authn/" + path if direct else get_vpn_url(config.IDP_BASE + "/idp/authn/" + path)
            request_headers = dict(public.headers) if direct else dict(headers)
            request_headers.update({"Cache-Control": "no-cache", "Pragma": "no-cache"})
            response = transport.post(endpoint("getAuthQr"),
                params={"_": time.time_ns()}, json={"entityId": original["entityId"], "lck": original["lck"]},
                headers=request_headers, timeout=30)
            response.raise_for_status()
            qr = response.json()
            if str(qr.get("code")) != "200":
                raise PermissionError("学校未能生成二次认证二维码；请重新运行")
            info = qr["data"]
            png = school_qr_png(info["qrMsg"])
            if not isinstance(info.get("qrToken"), str) or not info["qrToken"]:
                raise PermissionError("学校未返回有效的扫码会话")
            poll = {k: original[k] for k in ("entityId", "requestType", "lck")}
            poll.update(authModuleCode="qr", authChainCode=challenge["authChainCode"],
                        authPara={"qrToken": info["qrToken"]})
            if "requestNumber" in challenge:
                poll["requestNumber"] = challenge["requestNumber"]
                poll["authPara"]["loginName"] = challenge["userName"]
            # The school's UI starts this long request immediately after QR creation.
            # Keep it alive while publishing the encrypted image to GitHub.
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(transport.post, endpoint("authExecute"),
                    json=poll, headers=request_headers, timeout=(30, 300))
                time.sleep(1)
                if not future.done():
                    box.publish({"state": "waiting", "expires": int(time.time()) + 90,
                                 "png": base64.b64encode(png).decode()}, student, password)
                    print("[扫码确认] 学校确认连接已建立，请扫描本次任务二维码。", flush=True)
                try:
                    result = future.result()
                except requests.Timeout:
                    print("[扫码确认] 学校长连接等待超时，重新获取二维码。", flush=True)
                    continue
            result.raise_for_status()
            data = result.json()
            code = str(data.get("code"))
            message = str(data.get("message", ""))[:160].replace(student, "[account]").replace(password, "[redacted]")
            print(f"[扫码确认返回] route={'public' if direct else 'vpn'}; code={code}; second={data.get('second')}; token_present={bool(data.get('loginToken'))}; message={message}", flush=True)
            if code == "200" and data.get("loginToken") and not data.get("second"):
                outcome = "verified"
                print("[扫码验证] 学校已确认，继续同一次运行。", flush=True)
                return data["loginToken"]
            if code == "4005":
                box.publish({"state": "waiting", "expires": int(time.time()), "png": ""}, student, password)
                if not direct:
                    direct = True
                    print("[扫码确认] VPN 路径返回二维码失效，改用学校官方公网确认接口。", flush=True)
                else:
                    time.sleep(5)
                continue
            raise PermissionError(f"学校扫码确认未通过 (code={code}): {message}")
        raise PermissionError("扫码等待已满15分钟；请重新运行")
    finally:
        # Never let mailbox cleanup hide the original login failure.
        try:
            box.publish({"state": outcome, "expires": int(time.time()), "png": ""}, student, password)
        except requests.RequestException:
            print("[扫码验证] 状态更新失败；二维码将自动过期。", flush=True)
