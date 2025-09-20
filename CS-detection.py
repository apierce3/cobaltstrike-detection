import json, re, argparse
from collections import defaultdict

# Load JSONL events
def load_jsonl(path):
    return [json.loads(l) for l in open(path) if l.strip()]

# Heuristics patterns for Cobalt Strike
CS_HOSTS = ["powershell.exe","rundll32.exe","mshta.exe","cscript.exe"]
CS_CMD_PATTERNS = [r'Invoke-Expression','-enc','DownloadString','FromBase64String','iex']

# Scoring function
def score_event(ev):
    score, reasons = 0, []
    img, parent, cmd = (ev.get(k,"").lower() for k in ["Image","ParentImage","CommandLine"])
    if any(h in img for h in CS_HOSTS): score+=2; reasons.append("child_susp_host")
    if any(h in parent for h in CS_HOSTS): score+=1; reasons.append("parent_susp_host")
    if any(re.search(p, cmd, re.I) for p in CS_CMD_PATTERNS): score+=3; reasons.append("susp_cmdline")
    return score, reasons

# Correlate by process
def correlate(events, threshold=4):
    by_pid = defaultdict(list)
    for ev in events:
        pid = ev.get("ProcessId")
        if pid: by_pid[pid].append(ev)
    alerts=[]
    for pid, evs in by_pid.items():
        score, reasons = sum(score_event(e)[0] for e in evs), sum([score_event(e)[1] for e in evs], [])
        if score >= threshold: alerts.append({"ProcessId":pid,"Score":score,"Reasons":reasons})
    return alerts

# CLI
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", required=True, help="JSONL process events")
    parser.add_argument("--threshold", type=int, default=4)
    args = parser.parse_args()

    events = load_jsonl(args.events)
    alerts = correlate(events, args.threshold)
    if not alerts: print("[OK] No Cobalt Strike activity detected"); return
    for a in alerts: print(f"PID:{a['ProcessId']} Score:{a['Score']} Reasons:{','.join(a['Reasons'])}")

if __name__=="__main__":
    main()
