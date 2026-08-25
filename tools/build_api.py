#!/usr/bin/env python3
"""Build the static API: friendly JSON endpoints over the DOGG network's chains.

The chains are the verifiable record; these files are the convenience face — per-source
time series and latest-values, regenerated on a schedule, served free as static JSON
from GitHub Pages / raw. Every series row carries the frame hash it came from, so any
row can be audited back to the chain.
"""
import json, subprocess, pathlib, sys, datetime, shutil

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORK = ROOT / "_work"
API = ROOT / "api"
SPINE = "https://github.com/kody-w/dogg.git"

def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def main():
    if (WORK / "dogg" / ".git").is_dir():
        subprocess.run(["git", "-C", str(WORK / "dogg"), "pull", "-q", "--rebase"], check=True)
    else:
        WORK.mkdir(exist_ok=True)
        subprocess.run(["git", "clone", "-q", SPINE, str(WORK / "dogg")], check=True)
    sys.path.insert(0, str(WORK / "dogg" / "tools"))
    import chainio
    world = chainio.load_chain(WORK / "dogg" / "world")
    ticks_meta = json.loads((WORK / "dogg" / "ticks" / "HEAD.json").read_text())

    series = {}
    for f in world:
        p = f["payload"]
        for src, data in p.get("world", {}).items():
            series.setdefault(src, []).append(
                {"tick": p.get("tick"), "utc": p.get("fetched_utc"),
                 "frame": f["frame_hash"][:16], **({"v": data} if not isinstance(data, dict) else data)})
    if API.exists():
        shutil.rmtree(API)
    (API / "series").mkdir(parents=True)
    WINDOW = 1440   # rolling recent window (~10 days at 10-min ticks); the CHAINS are
                    # the forever-history — the API is a convenience view, so it must
                    # never grow without bound inside git history
    for src, rows in series.items():
        (API / "series" / f"{src}.json").write_text(json.dumps(
            {"source": src, "rows": rows[-WINDOW:], "window": WINDOW,
             "total_recorded": len(rows), "built_utc": utc(),
             "full_history": "walk the world/ chain at github.com/kody-w/dogg (epochs + tail)",
             "backing_chain": "world:@kody-w/dogg (kody-w/dogg /world)"},
            ensure_ascii=False) + "\n")
    latest = world[-1]["payload"]
    (API / "latest.json").write_text(json.dumps(
        {"tick": latest.get("tick"), "utc": latest.get("fetched_utc"),
         "world": latest.get("world", {}), "frame_hash": world[-1]["frame_hash"],
         "spine_head": ticks_meta["head_frame"], "built_utc": utc()},
        ensure_ascii=False, indent=1) + "\n")
    (API / "index.json").write_text(json.dumps(
        {"schema": "dogg/0-static-api", "built_utc": utc(),
         "endpoints": {"latest": "api/latest.json",
                       "series": {s: f"api/series/{s}.json" for s in sorted(series)}},
         "verify": "every row carries its source frame hash; chains at github.com/kody-w/dogg",
         "protocol": "https://github.com/kody-w/dogg/blob/main/PROTOCOL.md"},
        indent=1) + "\n")
    print(f"api built: {len(series)} series, {len(world)} world frames, latest tick {latest.get('tick')}")

if __name__ == "__main__":
    main()
