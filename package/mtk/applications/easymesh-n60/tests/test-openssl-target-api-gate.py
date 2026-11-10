#!/usr/bin/env python3
import importlib.util,tempfile
from pathlib import Path
p=Path(__file__).parents[1]/"scripts/enforce-openssl-target-api-gate.py"
spec=importlib.util.spec_from_file_location("target_api_gate",p)
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
with tempfile.TemporaryDirectory() as d:
 root=Path(d); src=root/"wappd"/"x.c"; src.parent.mkdir(); src.write_text("EVP_PKEY_cmp(a,b);\n")
 digest=m.sha256(src); git="a"*40
 inv=[{"component":"wappd","path":"wappd/x.c","line":"1","api":"EVP_PKEY_cmp","deprecated_macro":"OSSL_DEPRECATEDIN_3_0"}]
 call=[{"component":"wappd","path":"wappd/x.c","line":1,"api":"EVP_PKEY_cmp","reference_kind":"CALL_EXPRESSION","reachability_status":"ACTIVE","source_sha256":digest}]
 non=[]; macros=[]
 summary={"git_sha":git,"firmware_compile_invoked":False,"complete":True,"source_reachability_complete":True,
  "callsite_counts":{"total":1,"UNKNOWN_FAIL_CLOSED":0},
  "non_call_reference_counts":{"total":0,"UNKNOWN_FAIL_CLOSED":0},
  "macro_reference_counts":{"total":0,"UNKNOWN_FAIL_CLOSED":0}}
 unreviewed={"api":"EVP_PKEY_cmp","migration_status":"UNREVIEWED","approval":"false"}
 policy={"api_rules":{}}
 report=m.evaluate(inv,call,non,summary,macros,{"EVP_PKEY_cmp":unreviewed},policy,root,git)
 assert not report["complete"] and any("semantic review/approval" in x for x in report["failures"])
 # A source occurrence excluded by the exact N60 preprocessor is not an active API defect.
 call[0]["reachability_status"]="EXCLUDED_WITH_EVIDENCE"
 report=m.evaluate(inv,call,non,summary,macros,{"EVP_PKEY_cmp":unreviewed},policy,root,git)
 assert report["complete"] and report["excluded_with_evidence"]==1
 # A declaration/definition is inventoried but is not treated as an API invocation.
 call[0]["reference_kind"]="DECLARATION_OR_DEFINITION"
 call[0]["reachability_status"]="ACTIVE"
 non=[call[0]]; call=[]
 summary["callsite_counts"]["total"]=0; summary["non_call_reference_counts"]["total"]=1
 report=m.evaluate(inv,call,non,summary,macros,{"EVP_PKEY_cmp":unreviewed},policy,root,git)
 assert report["complete"] and report["declarations_or_definitions"]==1
 non[0]["reference_kind"]="CALL_EXPRESSION"
 non[0]["reachability_status"]="ACTIVE"
 # An active API with no migration-map row must fail closed.
 report=m.evaluate(inv,call,non,summary,macros,{},policy,root,git)
 assert not report["complete"] and any("missing from the migration map" in x for x in report["failures"])
 # An active call contradicting a lexical exclusion claim must fail closed.
 false_exclusion={"EVP_PKEY_cmp":{"migration_status":"UNREVIEWED","approval":"false","source_reachability_status":"UNREFERENCED_MACRO_DEFINITION"}}
 report=m.evaluate(inv,call,non,summary,macros,false_exclusion,policy,root,git)
 assert not report["complete"] and any("contradicts the migration map's exclusion claim" in x for x in report["failures"])
 # Unknown target reachability, missing evidence, and changed source bytes all fail closed.
 non[0]["reference_kind"]="UNKNOWN_REFERENCE_KIND"
 non[0]["reachability_status"]="UNKNOWN_FAIL_CLOSED"
 summary["non_call_reference_counts"]["UNKNOWN_FAIL_CLOSED"]=1
 report=m.evaluate(inv,call,non,summary,macros,{"EVP_PKEY_cmp":unreviewed},policy,root,git)
 assert not report["complete"] and report["unknown_fail_closed"]==1
 summary["non_call_reference_counts"]["UNKNOWN_FAIL_CLOSED"]=0
 report=m.evaluate(inv,call,[],summary,macros,{"EVP_PKEY_cmp":unreviewed},policy,root,git)
 assert not report["complete"] and any("lack exact target evidence" in x for x in report["failures"])
 non[0]["source_sha256"]="0"*64
 report=m.evaluate(inv,call,non,summary,macros,{"EVP_PKEY_cmp":unreviewed},policy,root,git)
 assert not report["complete"] and any("SHA256 mismatch" in x for x in report["failures"])
 # A matching hash outside the prepared component tree is not valid evidence.
 outside=root.parent/"outside.c"; outside.write_text("EVP_PKEY_cmp(a,b);\n")
 outside_row={"component":"wappd","path":"../outside.c","line":1,"api":"EVP_PKEY_cmp","reference_kind":"CALL_EXPRESSION","reachability_status":"EXCLUDED_WITH_EVIDENCE","source_sha256":m.sha256(outside)}
 outside_inv=[{"component":"wappd","path":"../outside.c","line":"1","api":"EVP_PKEY_cmp","deprecated_macro":"OSSL_DEPRECATEDIN_3_0"}]
 summary["callsite_counts"]={"total":1,"UNKNOWN_FAIL_CLOSED":0}; summary["non_call_reference_counts"]={"total":0,"UNKNOWN_FAIL_CLOSED":0}
 report=m.evaluate(outside_inv,[outside_row],[],summary,macros,{"EVP_PKEY_cmp":unreviewed},policy,root,git)
 assert not report["complete"] and any("escapes" in x for x in report["failures"])
 # An active call passes only with an explicit approved migration decision and policy.
 non=[]; call=[{"component":"wappd","path":"wappd/x.c","line":1,"api":"EVP_PKEY_cmp","reference_kind":"CALL_EXPRESSION","reachability_status":"ACTIVE","source_sha256":digest}]
 summary["callsite_counts"]={"total":1,"UNKNOWN_FAIL_CLOSED":0}; summary["non_call_reference_counts"]={"total":0,"UNKNOWN_FAIL_CLOSED":0}
 migration={"EVP_PKEY_cmp":{"migration_status":"APPROVED","approval":"true"}}
 policy={"api_rules":{"EVP_PKEY_cmp":{"status":"DIRECT_REPLACEMENT","reason":"Use EVP_PKEY_eq after confirming public-key equality semantics.","approved":True}}}
 report=m.evaluate(inv,call,non,summary,macros,migration,policy,root,git)
 assert not report["complete"] and any("still active" in x for x in report["failures"])
 policy={"api_rules":{"EVP_PKEY_cmp":{"status":"LEGACY_RETAINED","reason":"Retained temporarily for interoperability with the existing vendor protocol implementation; replacement requires end-to-end key equality regression evidence.","approved":True}}}
 report=m.evaluate(inv,call,non,summary,macros,migration,policy,root,git)
 assert report["complete"],report["failures"]
print("PASS: exact target reachability excludes inactive APIs and declarations; active, unknown, missing, stale and unapproved cases are handled fail-closed.")
