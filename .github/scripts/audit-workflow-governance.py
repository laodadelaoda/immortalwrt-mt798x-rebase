#!/usr/bin/env python3
from pathlib import Path
import yaml
R=Path(__file__).resolve().parents[2]; W=R/".github/workflows"; A=R/".github/actions/easymesh-quick/action.yml"
def bad(s): raise SystemExit("FAIL: "+s)
def load(p):
 try: x=yaml.load(p.read_text(encoding="utf-8"),Loader=yaml.BaseLoader)
 except Exception as e: bad(f"YAML syntax {p.relative_to(R)}: {e}")
 if not isinstance(x,dict): bad(f"invalid YAML mapping: {p}")
 return x
D={p.name:load(p) for p in W.glob("*.yml")}; act=load(A)
need={"main.yml","easymesh-quick.yml","vendor-source-patch-audit.yml","quick-prepare-audit.yml","quick-prepare-only.yml","wapp-source-audit.yml","conninfra-source-audit.yml","easymesh-wts-template-audit.yml","workflow-governance-audit.yml","openssl-migration-baseline-audit.yml","openssl-target-preprocessor-regression.yml","upstream-compatibility-audit.yml"}
if D.keys()!=need:
 bad("workflow set mismatch; missing="+str(sorted(need-D.keys()))+" extra="+str(sorted(D.keys()-need)))
ownership=(R/"docs/audit/WORKFLOW-OWNERSHIP.md")
if not ownership.is_file(): bad("frozen workflow ownership matrix is missing")
ownership_text=ownership.read_text(encoding="utf-8")
for n in sorted(need):
 if "`"+n+"`" not in ownership_text: bad("ownership matrix does not register "+n)
def tr(n): return D[n].get("on",{})
def steps(d):
 for j in d.get("jobs",{}).values():
  if isinstance(j,dict):
   for s in j.get("steps",[]):
    if isinstance(s,dict): yield s
main_triggers=tr("main.yml")
full_build=D["main.yml"].get("jobs",{}).get("build",{})
full_frozen=str(full_build.get("if","")).strip().lower()=="false"
if full_frozen:
 if set(main_triggers)!={"workflow_dispatch"}: bad("Full must remain manual-only while frozen")
elif set(main_triggers)=={"workflow_dispatch"}:
 pass
elif (set(main_triggers)=={"workflow_dispatch","push"} and
      main_triggers["push"].get("branches")==["n60pro-mtk-closed-driver"] and
      main_triggers["push"].get("paths")==[".github/workflows/main.yml"]):
 pass
else:
 bad("Unfrozen Full may use manual dispatch or the exact one-shot branch/path trigger only")

quick_triggers=tr("easymesh-quick.yml")
if set(quick_triggers)=={"workflow_dispatch"}:
 pass
elif (set(quick_triggers)=={"workflow_dispatch","push"} and
      quick_triggers["push"].get("branches")==["n60pro-mtk-closed-driver"] and
      quick_triggers["push"].get("paths")==[
       ".github/actions/easymesh-quick/action.yml",
       ".github/workflows/easymesh-quick.yml"]):
 pass
else:
 bad("Quick must be manual-only except for the exact one-shot source-build trigger")
vendor=tr("vendor-source-patch-audit.yml")
vendor_paths=[
 ".github/workflows/vendor-source-patch-audit.yml",
 ".github/workflows/quick-prepare-audit.yml",
 ".github/scripts/**",
 "config/n60pro-1001.config",
 "docs/audit/easymesh-patch-dependencies.csv",
 "docs/easymesh-patch-maintenance-groups.csv",
 "feeds.conf.default",
 "include/**",
 "Makefile",
 "package/kernel/mapfilter/**",
 "package/libs/libnl-tiny/**",
 "package/libs/openssl/**",
 "package/mtk/**",
 "package/vendor/**",
 "scripts/**",
 "target/linux/generic/patches-6.12/**",
 "target/linux/mediatek/patches-6.12/**",
 "target/linux/mediatek/tests/**",
]
# The canonical vendor audit is reusable, manually dispatchable, and
# independently triggerable by the preserved documentation trigger. The
# complete three-event contract is validated immediately below.
prepare_only=tr("quick-prepare-only.yml")
prepare_only_paths=vendor_paths+[".github/workflows/quick-prepare-only.yml"]
if (set(prepare_only)!={"push","workflow_dispatch"} or
    prepare_only["push"].get("branches")!=["n60pro-mtk-closed-driver"] or
    prepare_only["push"].get("paths")!=prepare_only_paths):
 bad("standalone Quick Prepare trigger mismatch")
if set(tr("quick-prepare-audit.yml"))!={"workflow_call"}: bad("Prepare must be reusable-only")
if set(vendor)!={"workflow_call","workflow_dispatch","push"}:
 bad("vendor audit must be reusable, manually dispatchable and docs-triggerable")
if vendor["push"].get("branches")!=["n60pro-mtk-closed-driver"] or vendor["push"].get("paths")!=["docs/vendor-patch-audit-trigger.txt"]:
 bad("standalone vendor audit docs trigger mismatch")
# Deep component source diagnostics are deliberately manual-only. The canonical
# vendor audit and native Prepare workflow own automatic Lock/patch gating.
for n in ("wapp-source-audit.yml","conninfra-source-audit.yml","easymesh-wts-template-audit.yml"):
 if set(tr(n))!={"workflow_dispatch"}:
  bad(n+" must remain an on-demand diagnostic, not a duplicate automatic gate")
baseline=tr("openssl-migration-baseline-audit.yml")
if set(baseline)!={"push","workflow_dispatch"}:
 bad("OpenSSL 68-item traceability baseline must run for every branch revision and remain manually dispatchable")
if baseline["push"].get("branches")!=["n60pro-mtk-closed-driver"] or baseline["push"].get("paths") is not None:
 bad("OpenSSL baseline must produce exact-SHA evidence on every maintenance-branch push")
if set(tr("workflow-governance-audit.yml"))!={"push"} or not tr("workflow-governance-audit.yml")["push"].get("paths"): bad("governance trigger mismatch")
preprocessor=tr("openssl-target-preprocessor-regression.yml")
if set(preprocessor)!={"push","pull_request","workflow_dispatch"}: bad("OpenSSL target preprocessor regression trigger mismatch")
for event in ("push","pull_request"):
 if not preprocessor[event].get("paths"): bad("OpenSSL target preprocessor regression must remain path-filtered")
 if event=="push" and preprocessor[event].get("branches")!=["n60pro-mtk-closed-driver"]: bad("OpenSSL target preprocessor push branch mismatch")
upstream=tr("upstream-compatibility-audit.yml")
if set(upstream)!={"workflow_dispatch","schedule"} or not upstream["schedule"]: bad("upstream compatibility audit must remain scheduled and manually dispatchable")
for n in ("main.yml","easymesh-quick.yml","vendor-source-patch-audit.yml","quick-prepare-audit.yml","quick-prepare-only.yml","openssl-migration-baseline-audit.yml"):
 if D[n].get("permissions",{}).get("contents")!="read": bad(n+" contents permission must be read")
for n in ("main.yml","workflow-governance-audit.yml","openssl-migration-baseline-audit.yml"):
 for s in steps(D[n]):
  if str(s.get("uses","")).startswith("actions/checkout@") and s.get("with",{}).get("persist-credentials")!="false": bad(n+" checkout credentials must be disabled")
for n in ("main.yml",):
 ss=[s for s in steps(D[n]) if s.get("uses","").startswith("actions/setup-node@")]
 if not ss or any(s.get("with",{}).get("node-version")!="24" for s in ss): bad(n+" Node must be 24")
ss=[s for s in act.get("runs",{}).get("steps",[]) if s.get("uses","").startswith("actions/setup-node@")]
if not ss or any(s.get("with",{}).get("node-version")!="24" for s in ss): bad("composite action Node must be 24")
mc=[s for s in steps(D["main.yml"]) if s.get("uses","").startswith("actions/cache@")]; keys=[s.get("with",{}).get("key","") for s in mc]
if not any("n60pro-full-openwrt-" in k and ".github/actions/easymesh-quick/action.yml" in k for k in keys): bad("Full cache key lacks phase prefix/action hash")
if not any("n60pro-full-ccache-" in k and "hashFiles(" in k for k in keys): bad("Full ccache key lacks config/toolchain hash")
if any(s.get("with",{}).get("restore-keys") for s in mc): bad("Full cache broad restore key present")
qc=[s for s in act.get("runs",{}).get("steps",[]) if s.get("uses","").startswith("actions/cache@")]
if not qc: bad("Quick cache missing")
qw=qc[0].get("with",{})
if "n60pro-quick-openwrt-" not in qw.get("key","") or ".github/actions/easymesh-quick/action.yml" not in qw.get("key","") or qw.get("restore-keys"): bad("Quick cache isolation/hash mismatch")
ver=(R/"package/mtk/applications/easymesh-n60/scripts/verify-vendor-audit-attestation.py").read_text()
for path in (".github/workflows/workflow-governance-audit.yml",
             ".github/scripts/audit-workflow-governance.py",
             ".github/scripts/check-package-dependency-closure.py",
             "package/mtk/applications/easymesh-n60/scripts/verify-vendor-audit-attestation.py"):
 if '"'+path+'"' not in ver: bad("vendor attestation does not bind "+path)
for fld in ('"commit_sha"','"lock_sha256"','"files"','"run_id"','"run_attempt"'):
 if fld not in ver: bad("attestation verifier missing "+fld)
for n in ("main.yml","easymesh-quick.yml"):
 ds=[s for s in steps(D[n]) if s.get("uses","").startswith("actions/download-artifact@")]
 if not any(s.get("with",{}).get("name")=="n60-vendor-audit-attestation" and "run-id" not in s.get("with",{}) for s in ds): bad(n+" attestation must be same-run")
 if not any("expected-run-id" in s.get("run","") and "expected-run-attempt" in s.get("run","") for s in steps(D[n])): bad(n+" run identity verification missing")
if not any(s.get("name")=="Download kernel patch stack attestation from same-run Prepare audit" for s in steps(D["main.yml"])): bad("kernel attestation provenance label incorrect")
for n,d in D.items():
 for s in steps(d):
  if s.get("uses","").startswith("actions/upload-artifact@") and not s.get("with",{}).get("retention-days"): bad(n+" artifact retention missing")
print(f"PASS: YAML syntax parsed for {len(D)} workflows and EasyMesh composite action")
print("PASS: trigger/call matrix, permissions, checkout credentials, Node.js 24")
print("PASS: Quick/Full cache isolation and cache-key policy")
print("PASS: same-run artifact provenance, attestation identity and retention")
print("PASS: vendor bypass boundary and attestation input binding")
