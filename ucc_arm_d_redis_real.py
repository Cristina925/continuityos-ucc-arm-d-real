#!/usr/bin/env python3
import json, subprocess, sys
from pathlib import Path

EVIDENCE = Path("evidence")
EVIDENCE.mkdir(exist_ok=True)
RESULTS = []

def redis(*args, check=True):
    p = subprocess.run(["redis-cli", "--raw", *map(str,args)], text=True, capture_output=True)
    if check and p.returncode != 0:
        raise RuntimeError(p.stderr or p.stdout)
    return p

def cap_key(cid): return f"cap:{cid}"
def sink_key(cid): return f"sink:{cid}"
def count_key(cid): return f"sink-count:{cid}"

def flush():
    redis("FLUSHDB")

def create_cap(cid, overrides=None):
    d = {
        "authorityState":"CURRENT",
        "authorityVersion":"1",
        "parentAuthorityVersion":"1",
        "actionDigest":"ACTION_A",
        "expiryState":"CURRENT",
    }
    if overrides: d.update(overrides)
    args=["HSET",cap_key(cid)]
    for k,v in d.items():
        args += [k,v]
    redis(*args)

def mutate(cid, changes):
    args=["HSET",cap_key(cid)]
    for k,v in changes.items():
        args += [k,v]
    redis(*args)

def read_hash(key):
    p=redis("HGETALL",key)
    vals=[x for x in p.stdout.splitlines() if x!=""]
    return dict(zip(vals[0::2],vals[1::2]))

def precheck(cid, expected_action="ACTION_A", expected_authority="1", expected_parent="1"):
    d=read_hash(cap_key(cid))
    if d.get("authorityState")!="CURRENT":
        return "BLOCKED_STALE_AUTHORITY"
    if d.get("authorityVersion")!=expected_authority:
        return "BLOCKED_STALE_AUTHORITY"
    if d.get("parentAuthorityVersion")!=expected_parent:
        return "BLOCKED_STALE_AUTHORITY"
    if d.get("actionDigest")!=expected_action:
        return "BLOCKED_ACTION_MISMATCH"
    if d.get("expiryState")!="CURRENT":
        return "BLOCKED_STALE_AUTHORITY"
    return "ALLOW"

def unconditional_commit(cid, commit_id):
    # Intentionally no authority/action/currentness read here.
    redis("HSET",sink_key(cid),"state","COMMITTED","commitId",commit_id)
    redis("INCR",count_key(cid))
    sink=read_hash(sink_key(cid))
    count=int(redis("GET",count_key(cid)).stdout.strip())
    return sink.get("state")=="COMMITTED" and sink.get("commitId")==commit_id, count

def observe_classification(cid, precheck_result, commit_performed, valid_at_commit, duplicate=False):
    if precheck_result != "ALLOW":
        return precheck_result
    if not commit_performed:
        return "LIVENESS_FAILURE"
    if duplicate or not valid_at_commit:
        return "COMMITTED_INVALID"
    return "COMMITTED_VALID"

def save():
    (EVIDENCE/"results.json").write_text(json.dumps(RESULTS,indent=2,sort_keys=True))

def record(cid, expected, observed, trace):
    rec={
        "case":cid,
        "expected":expected,
        "observed":observed,
        "pass":observed==expected,
        "trace":trace,
        "capability_after":read_hash(cap_key(cid)),
        "sink_after":read_hash(sink_key(cid)),
        "sink_count":int(redis("GET",count_key(cid)).stdout.strip() or "0") if redis("EXISTS",count_key(cid)).stdout.strip()=="1" else 0,
    }
    RESULTS.append(rec)
    (EVIDENCE/f"{cid}-result.json").write_text(json.dumps(rec,indent=2,sort_keys=True))
    if not rec["pass"]:
        (EVIDENCE/"FIRST-DISCREPANCY.json").write_text(json.dumps(rec,indent=2,sort_keys=True))
        save()
        print(json.dumps(rec,indent=2))
        print("FIRST DISCREPANCY FROZEN — STOPPING")
        sys.exit(2)
    print(f"{cid}: PASS expected={expected} observed={observed}")

def main():
    flush()

    # U01 legitimate
    create_cap("U01")
    pc=precheck("U01")
    committed,count=unconditional_commit("U01","U01-commit") if pc=="ALLOW" else (False,0)
    obs=observe_classification("U01",pc,committed,valid_at_commit=True)
    record("U01","COMMITTED_VALID",obs,["PRECHECK_ALLOW","UNCONDITIONAL_SINK_COMMIT"])

    # U02 invalid before precheck
    create_cap("U02",{"authorityState":"REVOKED"})
    pc=precheck("U02")
    obs=observe_classification("U02",pc,False,valid_at_commit=False)
    record("U02","BLOCKED_STALE_AUTHORITY",obs,["AUTHORITY_INVALID","PRECHECK"])

    # U03 invalidated before final precheck
    create_cap("U03")
    mutate("U03",{"authorityState":"REVOKED","authorityVersion":"2"})
    pc=precheck("U03",expected_authority="1")
    obs=observe_classification("U03",pc,False,valid_at_commit=False)
    record("U03","BLOCKED_STALE_AUTHORITY",obs,["AUTHORIZE","INVALIDATE","PRECHECK"])

    # U04 action changed before precheck
    create_cap("U04")
    mutate("U04",{"actionDigest":"ACTION_B"})
    pc=precheck("U04",expected_action="ACTION_A")
    obs=observe_classification("U04",pc,False,valid_at_commit=False)
    record("U04","BLOCKED_ACTION_MISMATCH",obs,["AUTHORIZE_A","ACTION_MUTATION_B","PRECHECK"])

    # U05 invalidate after successful precheck
    create_cap("U05")
    pc=precheck("U05")
    mutate("U05",{"authorityState":"REVOKED","authorityVersion":"2"})
    committed,count=unconditional_commit("U05","U05-commit") if pc=="ALLOW" else (False,0)
    obs=observe_classification("U05",pc,committed,valid_at_commit=False)
    record("U05","COMMITTED_INVALID",obs,["PRECHECK_ALLOW","INVALIDATION","UNCONDITIONAL_SINK_COMMIT"])

    # U06 revocation after precheck, before consequence
    create_cap("U06")
    pc=precheck("U06")
    mutate("U06",{"authorityState":"REVOKED","authorityVersion":"2"})
    committed,count=unconditional_commit("U06","U06-commit") if pc=="ALLOW" else (False,0)
    obs=observe_classification("U06",pc,committed,valid_at_commit=False)
    record("U06","COMMITTED_INVALID",obs,["PRECHECK_ALLOW","REVOCATION_SERIALIZES","UNCONDITIONAL_SINK_COMMIT"])

    # U07 commit first while authority current
    create_cap("U07")
    pc=precheck("U07")
    committed,count=unconditional_commit("U07","U07-commit") if pc=="ALLOW" else (False,0)
    mutate("U07",{"authorityState":"REVOKED","authorityVersion":"2"})
    obs=observe_classification("U07",pc,committed,valid_at_commit=True)
    record("U07","COMMITTED_VALID",obs,["PRECHECK_ALLOW","SINK_COMMIT_WHILE_CURRENT","REVOCATION_AFTER"])

    # U08 expiry after precheck, before consequence
    create_cap("U08")
    pc=precheck("U08")
    mutate("U08",{"expiryState":"EXPIRED"})
    committed,count=unconditional_commit("U08","U08-commit") if pc=="ALLOW" else (False,0)
    obs=observe_classification("U08",pc,committed,valid_at_commit=False)
    record("U08","COMMITTED_INVALID",obs,["PRECHECK_ALLOW","EXPIRY","UNCONDITIONAL_SINK_COMMIT"])

    # U09 replay same authorization -> second measurable consequence
    create_cap("U09")
    pc1=precheck("U09")
    c1,n1=unconditional_commit("U09","U09-first") if pc1=="ALLOW" else (False,0)
    pc2=precheck("U09")
    c2,n2=unconditional_commit("U09","U09-second") if pc2=="ALLOW" else (False,n1)
    obs="COMMITTED_INVALID" if c1 and c2 and n2>=2 else "LIVENESS_FAILURE"
    record("U09","COMMITTED_INVALID",obs,["PRECHECK_ALLOW","FIRST_COMMIT","REPLAY_PRECHECK_ALLOW","SECOND_COMMIT"])

    # U10 parent authority changes after precheck
    create_cap("U10")
    pc=precheck("U10",expected_parent="1")
    mutate("U10",{"parentAuthorityVersion":"2"})
    committed,count=unconditional_commit("U10","U10-commit") if pc=="ALLOW" else (False,0)
    obs=observe_classification("U10",pc,committed,valid_at_commit=False)
    record("U10","COMMITTED_INVALID",obs,["PRECHECK_ALLOW","PARENT_VERSION_CHANGE","UNCONDITIONAL_CHILD_COMMIT"])

    save()
    summary={"passed":sum(1 for r in RESULTS if r["pass"]),"total":len(RESULTS)}
    (EVIDENCE/"summary.json").write_text(json.dumps(summary,indent=2))
    print(f"RESULT: {summary['passed']}/{summary['total']} MATCHED FROZEN COMPARATOR ORACLE")

if __name__=="__main__":
    main()
