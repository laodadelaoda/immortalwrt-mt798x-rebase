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
need={"main.yml","easymesh-quick.yml","vendor-source-patch-audit.yml","quick-prepare-audit.yml","component-source-diagnostics.yml","workflow-governance-audit.yml","openssl-migration-baseline-audit.yml"}
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
if set(tr("quick-prepare-audit.yml"))!={"workflow_call"}: bad("Prepare must be reusable-only")
# Quick and Full share the same canonical vendor and Prepare gates, in that order.
for entry,build_job in (("easymesh-quick.yml","quick"),("main.yml","build")):
 jobs=D[entry].get("jobs",{})
 vendor_job=jobs.get("vendor_source_patch_audit",{})
 prepare_job=jobs.get("quick_prepare_audit",{})
 if vendor_job.get("uses")!="./.github/workflows/vendor-source-patch-audit.yml":
  bad(entry+" must call the canonical vendor audit")
 if prepare_job.get("uses")!="./.github/workflows/quick-prepare-audit.yml":
  bad(entry+" must call the canonical reusable Prepare audit")
 if prepare_job.get("needs")!="vendor_source_patch_audit":
  bad(entry+" Prepare must depend on the vendor audit")
 build=jobs.get(build_job,{})
 if set(build.get("needs",[]))!={"vendor_source_patch_audit","quick_prepare_audit"}:
  bad(entry+" build must hard-depend on both canonical gates")
 if entry=="main.yml" and str(build.get("if","")).strip().lower()!="false":
  bad("Full build must remain frozen")
# Quick Prepare must retrieve the baseline from a successful run for this exact
# SHA and verify the run-bound artifact ID and remote GitHub artifact digest.
prepare_text=(W/"quick-prepare-audit.yml").read_text(encoding="utf-8")
for token in ('--commit "$GITHUB_SHA"','BASELINE_RUN_ID','gh run download',
              'get("git_sha") != os.environ["GITHUB_SHA"]',
              'get("attempt")',"artifact['id']",'artifact.get("sha256"',
              'remote_json.get("workflow_run",{}).get("id")','remote != artifact["sha256"]'):
 if token not in prepare_text: bad("Quick Prepare OpenSSL baseline provenance check missing: "+token)
if set(vendor)!={"workflow_call","workflow_dispatch","push"}:
 bad("vendor audit must be reusable, manually dispatchable and docs-triggerable")
if vendor["push"].get("branches")!=["n60pro-mtk-closed-driver"] or vendor["push"].get("paths")!=["docs/vendor-patch-audit-trigger.txt"]:
 bad("standalone vendor audit docs trigger mismatch")
# Deep component source diagnostics are deliberately manual-only. The canonical
# vendor audit and native Prepare workflow own automatic Lock/patch gating.
if set(tr("component-source-diagnostics.yml"))!={"workflow_dispatch"}:
 bad("component diagnostics must be manual-only")
component_text=(W/"component-source-diagnostics.yml").read_text(encoding="utf-8")
for token in ("inputs.component == 'wapp'","inputs.component == 'conninfra'","inputs.component == 'wts'","inputs.component == 'upstream'","inputs.component == 'all'"):
 if token not in component_text: bad("consolidated component diagnostics missing selector: "+token)
baseline=tr("openssl-migration-baseline-audit.yml")
if set(baseline)!={"push","pull_request","workflow_dispatch"}:
 bad("OpenSSL 68-item traceability baseline must run for every branch revision and remain manually dispatchable")
if baseline["push"].get("branches")!=["n60pro-mtk-closed-driver"] or baseline["push"].get("paths") is not None:
 bad("OpenSSL baseline must produce exact-SHA evidence on every maintenance-branch push")
if not baseline["pull_request"].get("paths"):
 bad("OpenSSL regression coverage must remain path-filtered on pull requests")
if str(D["openssl-migration-baseline-audit.yml"].get("jobs",{}).get("header-baseline",{}).get("if",""))!="github.event_name != 'pull_request'":
 bad("68-item traceability archive scan must not run on pull requests")
if D["openssl-migration-baseline-audit.yml"].get("concurrency",{}).get("cancel-in-progress")!="true":
 bad("stale OpenSSL baseline runs must be cancelled when a newer SHA supersedes them")
if set(tr("workflow-governance-audit.yml"))!={"push"} or not tr("workflow-governance-audit.yml")["push"].get("paths"): bad("governance trigger mismatch")
openssl_jobs=D["openssl-migration-baseline-audit.yml"].get("jobs",{})
regression=openssl_jobs.get("target-preprocessor-regressions",{})
regression_text="\n".join(str(s.get("run","")) for s in regression.get("steps",[]))
for token in ("openssl-target-preprocessor-audit.py","test-openssl-target-preprocessor-audit.py","enforce-openssl-target-api-gate.py","test-openssl-target-api-gate.py"):
 if token not in regression_text: bad("canonical OpenSSL workflow missing merged regression check: "+token)
if not regression.get("steps"): bad("canonical OpenSSL workflow regression job is empty")
if not D["openssl-migration-baseline-audit.yml"].get("on",{}).get("pull_request",{}).get("paths"): bad("OpenSSL regression coverage must remain path-filtered on pull requests")
upstream_vendor=D["component-source-diagnostics.yml"].get("jobs",{}).get("upstream_vendor_audit",{})
upstream_impact=D["component-source-diagnostics.yml"].get("jobs",{}).get("upstream_impact",{})
if upstream_vendor.get("uses")!="./.github/workflows/vendor-source-patch-audit.yml":
 bad("upstream diagnostic must reuse the canonical vendor audit")
if upstream_impact.get("needs")!="upstream_vendor_audit":
 bad("upstream impact report must depend on the same-run vendor attestation producer")
if str(upstream_impact.get("if","")).replace(" ","")!="inputs.component=='upstream'||inputs.component=='all'":
 bad("upstream diagnostic selector/dependency condition mismatch")
upstream_steps=list(steps({"jobs":{"upstream_impact":upstream_impact}}))
upstream_text="\n".join(str(s.get("run",""))+" "+str(s.get("with","")) for s in upstream_steps)
for token in ("n60-upstream-compat-audit.py","verify-vendor-audit-attestation.py",
              "--expected-run-id","--expected-run-attempt","n60-upstream-compatibility-evidence"):
 if token not in upstream_text: bad("upstream diagnostic lost required evidence/report step: "+token)
if not any(s.get("with",{}).get("retention-days")=="90" for s in upstream_steps if s.get("uses","").startswith("actions/upload-artifact@")):
 bad("upstream compatibility evidence retention must remain 90 days")
for n in ("main.yml","easymesh-quick.yml","vendor-source-patch-audit.yml","quick-prepare-audit.yml","component-source-diagnostics.yml","openssl-migration-baseline-audit.yml"):
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
             ".github/workflows/openssl-migration-baseline-audit.yml",
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
