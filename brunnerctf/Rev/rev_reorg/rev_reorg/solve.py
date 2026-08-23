import re, itertools
from pathlib import Path

# --- load maps ---
def load_map(path):
    m={}
    for line in Path(path).read_text().splitlines():
        line=line.strip()
        if not line or line.startswith("default"): continue
        # "key" "val";
        a=re.findall(r'"([^"]*)"', line)
        if len(a)>=2: m[a[0]]=a[1]
    # default
    txt=Path(path).read_text()
    d=re.search(r'default\s+"([^"]*)"', txt)
    default = d.group(1) if d else "!"
    return m, default

bands,_ = load_map("reorg-bands.conf")
ledger,_ = load_map("reorg-ledger.conf")
legal,_  = load_map("reorg-legal.conf")
ops,_    = load_map("reorg-ops.conf")
sales,_  = load_map("reorg-sales.conf")

default_conf = Path("default.conf").read_text()

# seats: pos -> seat_name
seat_pos={}
for m in re.finditer(r'map \$route \$(\w+) \{[^\}]*"~\^\.\{(\d+)\}', default_conf):
    seat_pos[int(m.group(2))] = m.group(1)
# order 0..39
seats_ordered = [seat_pos[i] for i in range(40)]

# seat -> band var
seat_to_band={}
for m in re.finditer(r'map \$(\w+) \$(\w+) \{ include reorg-bands\.conf', default_conf):
    seat_to_band[m.group(1)] = m.group(2)

# ledger chain: map "${A}${B}" $C { include reorg-ledger }
ledger_steps=[]
for m in re.finditer(r'map "\$\{([^}]+)\}\$\{([^}]+)\}" \$(\w+) \{ include reorg-ledger', default_conf):
    ledger_steps.append((m.group(1), m.group(2), m.group(3)))
# ledger_d1d8 init
# band -> legal/ops/sales
band_to_reviews={}
for m in re.finditer(r'map \$(\w+) \$(\w+) \{ include reorg-(legal|ops|sales)\.conf', default_conf):
    band_to_reviews.setdefault(m.group(1), []).append((m.group(2), m.group(3)))
ledger_to_reviews={}
for m in re.finditer(r'map \$(\w+) \$(\w+) \{ include reorg-(legal|ops|sales)\.conf', default_conf):
    pass # already captured above, separate

# tier/review
tier_review_to_next={}
for m in re.finditer(r'map "\$\{([^}]+)\}:\$\{([^}]+)\}" \$(\w+) \{([^}]+)\}', default_conf, re.DOTALL):
    tier, rev, nxt, body = m.group(1), m.group(2), m.group(3), m.group(4)
    mp={}
    for kv in re.finditer(r'"([^"]+)"\s+"([^"]+)"', body):
        mp[kv.group(1)] = kv.group(2)
    tier_review_to_next[(tier,rev)] = mp

audits=[]
for m in re.finditer(r'map "\$\{([^}]+)\}(?:\$\{([^}]+)\})+" \$(\w+) \{ default 0; "~\^.*', default_conf):
    # easier: parse audit lines directly
    pass
# hard-coded audits from your paste
audit_groups=[
    ["band_7226","band_1799"],
    ["band_bd4f","band_c5fe","band_f8dc"],
    ["band_80c3","band_08f9"],
    ["band_2dba","band_785f","band_d337","band_69b5","band_251b"],
    ["band_903e","band_36a2"],
    ["band_fa6e","band_c884"],
]

# Allowed chars for route: what bands maps from? bands keys are a-z0-9_{}
alphabet = list(bands.keys())  # 39 chars

# Precompute inverse for pruning? forward search DFS
from functools import lru_cache

# Build helper to compute bands quickly
def compute_bands(route):
    bands_vals={}
    for i,ch in enumerate(route):
        seat = seats_ordered[i]
        band_var = seat_to_band[seat]
        bands_vals[band_var] = bands.get(ch, "!")
    return bands_vals

def compute_ledgers(bands_vals):
    ledgers={"ledger_d1d8":"Q"}
    # need to follow ledger_steps in correct dependency order - already topological
    for a,b,c in ledger_steps:
        # a is ledger var or band var? check which dict
        va = ledgers.get(a, bands_vals.get(a, None))
        vb = ledgers.get(b, bands_vals.get(b, None))
        if va is None or vb is None:
            return None
        key = va+vb
        ledgers[c] = ledger.get(key, "!")
    return ledgers

# DFS with audit pruning
route=['']*40
best=None
# order positions by most constrained: audit groups first
order = []
seen=set()
for grp in audit_groups:
    for bv in grp:
        # find which seat maps to this band
        for seat,band in seat_to_band.items():
            if band==bv and seat not in seen:
                # find pos of seat
                for pos,s in enumerate(seats_ordered):
                    if s==seat:
                        order.append(pos)
                        seen.add(seat)
for i in range(40):
    if i not in order:
        order.append(i)

import sys
sys.setrecursionlimit(10000)
cand = 0
def dfs(idx):
    global best, cand
    if best: return True
    if idx==40:
        r=''.join(route)
        bv=compute_bands(r)
        if any(v=="!" for v in bv.values()): return False
        # audit
        for grp in audit_groups:
            vals=[bv[g] for g in grp]
            if len(set(vals))!=1: return False
        led=compute_ledgers(bv)
        if led is None or any(v=="!" for v in led.values()): return False
        # tier walk - implement quickly via default.conf logic
        # ... check CLEARED
        # For brevity: emulate nginx maps for tier/review with same code
        # If passes, print route and flag candidate
        cand+=1
        # try to check $access condition via actual nginx is heavy, just try request locally with docker if you have it:
        # docker compose up and curl http://localhost:80/<route>
        print("candidate",r, bv, led)
        return False
    pos = order[idx]
    seat = seats_ordered[pos]
    band_var = seat_to_band[seat]
    # prune audit: if this band belongs to group, try to enforce equality
    for ch in alphabet:
        route[pos]=ch
        # quick audit prune
        bv_partial = {seat_to_band[seats_ordered[p]]: bands.get(route[p],"!") for p in range(40) if route[p]!=''}
        # if group has two assigned and mismatch -> prune
        ok=True
        for grp in audit_groups:
            vals=[bv_partial.get(g) for g in grp if g in bv_partial]
            if len(set(v for v in vals if v))>1:
                ok=False; break
        if not ok: continue
        if dfs(idx+1): return True
    route[pos]=''
    return False

# Start - this may take minutes, but audits prune heavily
dfs(0)