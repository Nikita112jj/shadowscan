# -*- coding: utf-8 -*-
# Регресс-тест ShadowScan CLI: файл -> вердикт/скор + признаки деобфускации
import json, subprocess, sys, os

EXE = r"D:\колизион\antivirus\ShadowScan.exe"

def run(files):
    cmd = [EXE, "--scan"] + files
    out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    try:
        return json.loads(out.stdout)
    except Exception:
        print("RAW:", out.stdout[:300], out.stderr[:300])
        return []

def show(results):
    for r in results:
        deobf = [f["Detail"] for f in r["Findings"] if f.get("Category") == "deobfuscated"]
        ded = (" | " + "; ".join(deobf)) if deobf else ""
        print(f"{os.path.basename(r['File']):16} {r['Verdict']:11} {r['Score']:3}  {r.get('ThreatType','')}{ded}")

if __name__ == "__main__":
    files = sys.argv[1:]
    if files:
        show(run(files))
    else:
        # режим stdin: JSON из пайпа
        import json
        show(json.load(sys.stdin))
