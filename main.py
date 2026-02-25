import requests
import base64
import json

INPUT_FILE = "inputs.txt"
OUTPUT_FILE = "output.txt"
TIMEOUT = 10


def fetch(url):
    try:
        r = requests.get(url, timeout=TIMEOUT)
        if r.status_code == 200:
            return r.text.strip()
    except:
        pass
    return None


def try_decode(text):
    for _ in range(3):
        try:
            decoded = base64.b64decode(text).decode("utf-8")
            if decoded.strip():
                text = decoded
        except:
            break
    return text


def extract_configs(text):
    lines = text.split("\n")
    valid = []
    for l in lines:
        l = l.strip()
        if l.startswith(("vmess://","vless://","trojan://","ss://","ssr://","hy2://","tuic://")):
            valid.append(l)
    return valid


# ==============================
# 🔥 Professional Fingerprint
# ==============================

def fingerprint(line):

    try:

        if line.startswith("vmess://"):
            raw = line.split("://")[1].split("#")[0]
            data = json.loads(base64.b64decode(raw).decode("utf-8"))
            return "|".join([
                "vmess",
                data.get("add",""),
                str(data.get("port","")),
                data.get("id",""),
                data.get("net",""),
                data.get("path",""),
                data.get("host",""),
                data.get("tls","")
            ])

        if line.startswith("vless://"):
            main = line.split("#")[0]
            body = main.replace("vless://","")
            return "vless|" + body

        if line.startswith("trojan://"):
            main = line.split("#")[0]
            body = main.replace("trojan://","")
            return "trojan|" + body

        return line.split("#")[0]

    except:
        return line


def main():

    collected = []

    with open(INPUT_FILE) as f:
        sources = [line.strip() for line in f if line.strip()]

    for url in sources:
        data = fetch(url)
        if not data:
            continue

        data = try_decode(data)
        configs = extract_configs(data)
        collected.extend(configs)

    # ==============================
    # Dedup حرفه‌ای
    # ==============================

    seen = set()
    final = []

    for line in collected:
        key = fingerprint(line)
        if key in seen:
            continue
        seen.add(key)
        final.append(line)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(final))


if __name__ == "__main__":
    main()
