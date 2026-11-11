#!/usr/bin/env python3
import csv,importlib.util,tempfile
from pathlib import Path
p=Path(__file__).parents[1]/"scripts/enforce-openssl-target-api-gate.py"
spec=importlib.util.spec_from_file_location("target_api_gate",p)
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
with tempfile.TemporaryDirectory() as d:
 root=Path(d); src=root/"wappd"/"x.c"; src.parent.mkdir(); src.write_text('#if 0\nEVP_PKEY_cmp(a,b);\n#endif\nint f(void) { return 0; }\n')
 # GCC may emit relative #line filenames for sources under the component cwd.
 # Independent gate verification must resolve those markers against the exact TU cwd.
 relative_root=root/"relative-build"/"wappd"; (relative_root/"src").mkdir(parents=True)
 relative_source=relative_root/"src"/"relative.c"
 relative_source.write_text("EVP_PKEY_cmp(a,b);\n")
 relative_pp=root/"relative.i"
 relative_pp.write_text('# 1 "src/relative.c"\nEVP_PKEY_cmp(a,b);\n')
 assert m.observe_preprocessed_output(relative_pp,relative_source.resolve(),1,"EVP_PKEY_cmp",relative_root)==(True,True)
 assert m.observe_preprocessed_output(relative_pp,relative_source.resolve(),1,"EVP_PKEY_cmp",root)==(False,False)
 digest=m.sha256(src); git="a"*40
 inv=[{"component":"wappd","path":"wappd/x.c","line":"2","api":"EVP_PKEY_cmp","deprecated_macro":"OSSL_DEPRECATEDIN_3_0"}]
 call=[{"component":"wappd","path":"wappd/x.c","line":2,"api":"EVP_PKEY_cmp","reference_kind":"CALL_EXPRESSION","reachability_status":"ACTIVE","source_sha256":digest,"conditional_branch_path":[]}]
 non=[]; macros=[]
 summary={"git_sha":git,"firmware_compile_invoked":False,"complete":True,"source_reachability_complete":True,
  "callsite_counts":{"total":1,"UNKNOWN_FAIL_CLOSED":0},
  "non_call_reference_counts":{"total":0,"UNKNOWN_FAIL_CLOSED":0},
  "macro_reference_counts":{"total":0,"UNKNOWN_FAIL_CLOSED":0}}
 unreviewed={"api":"EVP_PKEY_cmp","migration_status":"UNREVIEWED","approval":"false"}
 policy={"api_rules":{}}
 report=m.evaluate(inv,call,non,summary,macros,{"EVP_PKEY_cmp":unreviewed},policy,root,git)
 assert not report["complete"] and any("remains unapproved" in x for x in report["failures"])
 # A source occurrence excluded by the exact N60 preprocessor is not an active API defect.
 call[0]["reachability_status"]="EXCLUDED_WITH_EVIDENCE"
 # A bare status label is not evidence: the exact source must be a successful
 # target translation unit, and the negative observation must bind its hashes.
 report=m.evaluate(inv,call,non,summary,macros,{"EVP_PKEY_cmp":unreviewed},policy,root,git)
 assert not report["complete"] and any("negative target-preprocessor proof" in x for x in report["failures"])
 # The referenced file is an included-source candidate, not a top-level TU.
 # Every TU in the completed component graph must be inspected; one TU that
 # emits the source line invalidates the negative proof.
 main1=root/"wappd"/"main1.c"; main1.write_text('#include "x.c"\n')
 main2=root/"wappd"/"main2.c"; main2.write_text("int other(void) { return 0; }\n")
 ppout=root/"unit1.i"; ppout.write_text(f'# 4 "{src.resolve()}"\nint f(void) {{ return 0; }}\n')
 ppout2=root/"unit2.i"; ppout2.write_text(f'# 1 "{main2.resolve()}"\nint other(void) {{ return 0; }}\n')
 pp_digest=m.sha256(ppout); pp_digest2=m.sha256(ppout2)
 tu={"source":str(main1.resolve()),"returncode":0,"preprocessed_sha256":pp_digest,"preprocessed_output":str(ppout.resolve())}
 tu2={"source":str(main2.resolve()),"returncode":0,"preprocessed_sha256":pp_digest2,"preprocessed_output":str(ppout2.resolve())}
 summary["components"]={"wappd":{"source_reachability_complete":True,"translation_units":[tu,tu2]}}
 summary["evidence_output_dir"]=str(root)
 call[0]["conditional_branch_path"]=[]
 call[0]["preprocessor_negative_evidence"]={
  "source_is_direct_translation_unit":False,"component_compile_graph_complete":True,"api_hit_absent":True,
  "source_line_absent_from_all_target_preprocessing":True,
  "preprocessed_translation_units":[{"source":str(main1.resolve()),"preprocessed_sha256":pp_digest},
                                    {"source":str(main2.resolve()),"preprocessed_sha256":pp_digest2}],
  "target_compiler_sha256":"2"*64,"target_config_sha256":"3"*64,
  "source_sha256":digest,"conditional_branch_path":[]}
 summary["target_compiler_sha256"]="2"*64; summary["target_config_sha256"]="3"*64
 report=m.evaluate(inv,call,non,summary,macros,{"EVP_PKEY_cmp":unreviewed},policy,root,git)
 assert report["complete"] and report["excluded_with_evidence"]==1,report["failures"]
 # Omitting a component TU from the signed negative evidence must fail.
 call[0]["preprocessor_negative_evidence"]["preprocessed_translation_units"].pop()
 report=m.evaluate(inv,call,non,summary,macros,{"EVP_PKEY_cmp":unreviewed},policy,root,git)
 assert not report["complete"] and any("negative target-preprocessor proof" in x for x in report["failures"])
 call[0]["preprocessor_negative_evidence"]["preprocessed_translation_units"].append({"source":str(main2.resolve()),"preprocessed_sha256":pp_digest2})
 # If any TU emits the exact source line, the source cannot be excluded.
 ppout2.write_text(f'# 2 "{src.resolve()}"\nEVP_PKEY_cmp(a,b);\n')
 active_digest=m.sha256(ppout2); tu2["preprocessed_sha256"]=active_digest
 call[0]["preprocessor_negative_evidence"]["preprocessed_translation_units"][1]["preprocessed_sha256"]=active_digest
 report=m.evaluate(inv,call,non,summary,macros,{"EVP_PKEY_cmp":unreviewed},policy,root,git)
 assert not report["complete"] and any("negative target-preprocessor proof" in x for x in report["failures"])
 ppout2.write_text(f'# 1 "{main2.resolve()}"\nint other(void) {{ return 0; }}\n')
 pp_digest2=m.sha256(ppout2); tu2["preprocessed_sha256"]=pp_digest2
 call[0]["preprocessor_negative_evidence"]["preprocessed_translation_units"][1]["preprocessed_sha256"]=pp_digest2
 # A mismatched conditional path must revoke the exclusion proof.
 call[0]["preprocessor_negative_evidence"]["conditional_branch_path"]=["#if 0"]
 report=m.evaluate(inv,call,non,summary,macros,{"EVP_PKEY_cmp":unreviewed},policy,root,git)
 assert not report["complete"] and any("negative target-preprocessor proof" in x for x in report["failures"])
 call[0]["preprocessor_negative_evidence"]["conditional_branch_path"]=[]
 # Falsifying any one observation must revoke exclusion.
 call[0]["preprocessor_negative_evidence"]["api_hit_absent"]=False
 report=m.evaluate(inv,call,non,summary,macros,{"EVP_PKEY_cmp":unreviewed},policy,root,git)
 assert not report["complete"] and any("negative target-preprocessor proof" in x for x in report["failures"])
 call[0]["preprocessor_negative_evidence"]["api_hit_absent"]=True
 # A self-consistent forged proof cannot hide an API call present in the actual .i file.
 ppout.write_text(f'# 2 "{src.resolve()}"\nEVP_PKEY_cmp(a,b);\n')
 forged_digest=m.sha256(ppout)
 tu["preprocessed_sha256"]=forged_digest
 call[0]["preprocessor_negative_evidence"]["preprocessed_translation_units"][0]["preprocessed_sha256"]=forged_digest
 report=m.evaluate(inv,call,non,summary,macros,{"EVP_PKEY_cmp":unreviewed},policy,root,git)
 assert not report["complete"] and any("negative target-preprocessor proof" in x for x in report["failures"])
 ppout.write_text(f'# 4 "{src.resolve()}"\nint f(void) {{ return 0; }}\n')
 restored_digest=m.sha256(ppout)
 tu["preprocessed_sha256"]=restored_digest
 call[0]["preprocessor_negative_evidence"]["preprocessed_translation_units"][0]["preprocessed_sha256"]=restored_digest

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
 assert not report["complete"] and any("missing from the 40-API semantic review CSV" in x for x in report["failures"])
 # An active call contradicting a lexical exclusion claim must fail closed.
 false_exclusion={"EVP_PKEY_cmp":{"migration_status":"UNREVIEWED","approval":"false","source_reachability_status":"UNREFERENCED_MACRO_DEFINITION"}}
 report=m.evaluate(inv,call,non,summary,macros,false_exclusion,policy,root,git)
 assert not report["complete"] and any("remains unapproved" in x for x in report["failures"])
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
 outside_row={"component":"wappd","path":"../outside.c","line":2,"api":"EVP_PKEY_cmp","reference_kind":"CALL_EXPRESSION","reachability_status":"EXCLUDED_WITH_EVIDENCE","source_sha256":m.sha256(outside)}
 outside_inv=[{"component":"wappd","path":"../outside.c","line":"2","api":"EVP_PKEY_cmp","deprecated_macro":"OSSL_DEPRECATEDIN_3_0"}]
 summary["callsite_counts"]={"total":1,"UNKNOWN_FAIL_CLOSED":0}; summary["non_call_reference_counts"]={"total":0,"UNKNOWN_FAIL_CLOSED":0}
 report=m.evaluate(outside_inv,[outside_row],[],summary,macros,{"EVP_PKEY_cmp":unreviewed},policy,root,git)
 assert not report["complete"] and any("escapes" in x for x in report["failures"])
 # An active call passes only with an explicit approved migration decision and policy.
 non=[]; call=[{"component":"wappd","path":"wappd/x.c","line":2,"api":"EVP_PKEY_cmp","reference_kind":"CALL_EXPRESSION","reachability_status":"ACTIVE","source_sha256":digest}]
 summary["callsite_counts"]={"total":1,"UNKNOWN_FAIL_CLOSED":0}; summary["non_call_reference_counts"]={"total":0,"UNKNOWN_FAIL_CLOSED":0}
 migration={"EVP_PKEY_cmp":{"migration_status":"LEGACY_RETAINED","approval":"true"}}
 policy={"api_rules":{"EVP_PKEY_cmp":{"status":"DIRECT_REPLACEMENT","reason":"Use EVP_PKEY_eq after confirming public-key equality semantics.","approved":True}}}
 report=m.evaluate(inv,call,non,summary,macros,migration,policy,root,git)
 assert not report["complete"] and any("still active" in x for x in report["failures"])
 policy={"api_rules":{"EVP_PKEY_cmp":{"status":"LEGACY_RETAINED","reason":"Retained temporarily for interoperability with the existing vendor protocol implementation; replacement requires end-to-end key equality regression evidence.","approved":True}}}
 report=m.evaluate(inv,call,non,summary,macros,migration,policy,root,git)
 assert report["complete"],report["failures"]
 # A macro cannot be excluded by a caller-supplied status without lexical and source-hash proof.
 macro={"component":"wappd","path":"wappd/x.c","line":1,"macro":"WRAP","api":"EVP_PKEY_cmp",
  "reachability":"ACTIVE_MACRO_EXPANSION_REQUIRES_CPP","reachability_status":"EXCLUDED_WITH_EVIDENCE",
  "reason":"macro definition has no lexical reference in the component and target preprocessing completed",
  "source_sha256":digest}
 report=m.evaluate([],[],[],{"git_sha":git,"firmware_compile_invoked":False,"complete":True,
  "source_reachability_complete":True,"callsite_counts":{"total":0,"UNKNOWN_FAIL_CLOSED":0},
  "non_call_reference_counts":{"total":0,"UNKNOWN_FAIL_CLOSED":0},"macro_reference_counts":{"total":1,"UNKNOWN_FAIL_CLOSED":0},
  "components":{"wappd":{"source_reachability_complete":True}}},[macro],{},{"api_rules":{}},root,git)
 assert not report["complete"] and any("macro EXCLUDED_WITH_EVIDENCE" in x for x in report["failures"])
# A lexical macro exclusion is invalid if target preprocessing found the API
# active anywhere in the same component (including token-paste expansion).
active_call={"component":"wappd","path":"wappd/x.c","line":2,"api":"EVP_PKEY_cmp",
 "reference_kind":"CALL_EXPRESSION","reachability_status":"ACTIVE","source_sha256":digest}
active_inventory=[{"component":"wappd","path":"wappd/x.c","line":"2","api":"EVP_PKEY_cmp",
 "deprecated_macro":"OSSL_DEPRECATEDIN_3_0"}]
forged_macro={"component":"wappd","path":"wappd/x.c","line":2,"api":"EVP_PKEY_cmp","macro":"WRAP",
 "reachability":"UNREFERENCED_MACRO_DEFINITION","reachability_status":"EXCLUDED_WITH_EVIDENCE",
 "reason":"macro definition is lexically unreferenced and no target-preprocessed API call exists in the component",
 "source_sha256":digest}
macro_summary={"git_sha":git,"firmware_compile_invoked":False,"complete":True,
 "source_reachability_complete":True,"callsite_counts":{"total":1,"UNKNOWN_FAIL_CLOSED":0},
 "non_call_reference_counts":{"total":0,"UNKNOWN_FAIL_CLOSED":0},
 "macro_reference_counts":{"total":1,"UNKNOWN_FAIL_CLOSED":0},
 "components":{"wappd":{"source_reachability_complete":True}}}
report=m.evaluate(active_inventory,[active_call],[],macro_summary,[forged_macro],{},{"api_rules":{}},root,git)
assert not report["complete"] and any("macro exclusion contradicts an active target-preprocessor API hit" in x for x in report["failures"]),report["failures"]


# Preserve the 68-row global candidate map while deriving only target-ACTIVE
# EasyMesh API calls as the migration-required subset.
subset=m.build_easymesh_api_subset(
 [{"component":"wappd","path":"wappd/a.c","line":10,"api":"EVP_PKEY_cmp","deprecated_macro":"OSSL_DEPRECATEDIN_3_0"},
  {"component":"1905daemon","path":"1905daemon/b.c","line":20,"api":"EC_KEY_new","deprecated_macro":"OSSL_DEPRECATEDIN_3_0"},
  {"component":"wappd","path":"wappd/c.c","line":30,"api":"ENGINE_by_id","deprecated_macro":"OSSL_DEPRECATEDIN_3_0"}],
 [{"component":"wappd","path":"wappd/a.c","line":10,"api":"EVP_PKEY_cmp","reference_kind":"CALL_EXPRESSION","reachability_status":"ACTIVE"},
  {"component":"1905daemon","path":"1905daemon/b.c","line":20,"api":"EC_KEY_new","reference_kind":"CALL_EXPRESSION","reachability_status":"EXCLUDED_WITH_EVIDENCE"},
  {"component":"wappd","path":"wappd/c.c","line":30,"api":"ENGINE_by_id","reference_kind":"CALL_EXPRESSION","reachability_status":"EXCLUDED_WITH_EVIDENCE"}],
 [],[],{"EVP_PKEY_cmp":{"migration_status":"UNREVIEWED","approval":"false"},
         "EC_KEY_new":{"migration_status":"UNREVIEWED","approval":"false"},
         "ENGINE_by_id":{"migration_status":"UNREVIEWED","approval":"false"}},[])
assert len(subset)==3
assert [x["api"] for x in subset if x["needs_migration_review"]]==["EVP_PKEY_cmp"]
assert next(x for x in subset if x["api"]=="ENGINE_by_id")["scope_status"]=="EXCLUDED_WITH_EVIDENCE"
assert next(x for x in subset if x["api"]=="EC_KEY_new")["needs_migration_review"] is False

removed=m.build_easymesh_api_subset([],[],[],[],
 {"EVP_MD_CTX_md":{"observed_lexical_occurrences":"2","observed_components":"wappd;1905daemon","migration_status":"UNREVIEWED","approval":"false"}},
 [{"api":"EVP_MD_CTX_md","pristine_calls":"2","prepared_calls":"0","delta":"-2","deprecated":"True"}])
assert len(removed)==1 and removed[0]["scope_status"]=="NO_LONGER_PRESENT_AFTER_PATCH"
assert removed[0]["requires_patch_semantic_review"] is True and removed[0]["needs_migration_review"] is False
unknown_removed=m.build_easymesh_api_subset([],[],[],[],
 {"EVP_MD_CTX_md":{"observed_lexical_occurrences":"2","observed_components":"wappd","migration_status":"UNREVIEWED","approval":"false"}},[])
assert unknown_removed[0]["scope_status"]=="UNKNOWN_FAIL_CLOSED"


# A source-removal delta is not silently treated as a completed migration.
removed_row={"api":"EVP_MD_CTX_md","requires_patch_semantic_review":True}
unreviewed_removed={"EVP_MD_CTX_md":{"migration_status":"UNREVIEWED","approval":"false"}}
assert m.validate_removed_api_reviews([removed_row],unreviewed_removed,{})
approved_removed={"EVP_MD_CTX_md":{"migration_status":"MIGRATED","approval":"true"}}
assert m.validate_removed_api_reviews([removed_row],approved_removed,{}) 
assert not m.validate_removed_api_reviews([removed_row],approved_removed,
 {"api_rules":{"EVP_MD_CTX_md":{"status":"SEMANTIC_ADAPTATION","approved":True,"reason":"The removed call is replaced with a semantically equivalent EVP accessor."}}})

scope={"schema_version":1,"scope_id":"n60-easymesh-openssl-3.5.9","openssl_version":"3.5.9",
 "primary_components":["wappd","mapd","1905daemon","libmapd"],
 "supporting_dependencies":[{"name":"datconf"},{"name":"libnl-tiny"}],
 "global_baseline":{"path":"package/mtk/applications/easymesh-n60/tests/openssl-111-to-359-migration-map.csv","expected_rows":68,"role":"TRACEABILITY_ONLY","is_migration_approval":False}}
scope_summary={"components":{x:{} for x in scope["primary_components"]}}
scope_map={f"api{i}":{} for i in range(68)}
assert m.validate_scope_manifest(scope,scope_summary,scope_map)==[]
assert m.validate_scope_manifest({**scope,"primary_components":["wappd"]},scope_summary,scope_map)
assert m.validate_scope_manifest({**scope,"global_baseline":{"expected_rows":68,"role":"MIGRATION_APPROVAL","is_migration_approval":True}},scope_summary,scope_map)

# The semantic review is a separate, non-approval record: preserve all 40
# target-active APIs and their 348 baseline callsites without pre-approving them.
review_path=Path(__file__).with_name("openssl-40-active-api-semantic-review.csv")
with review_path.open(encoding="utf-8",newline="") as f:
 review_rows=list(csv.DictReader(f))
assert len(review_rows)==40
assert len({x["api"] for x in review_rows})==40
assert sum(int(x["active_call_sites"]) for x in review_rows)==348
allowed_review_statuses={"REVIEWED_PENDING_IMPLEMENTATION","IMPLEMENTED_PENDING_VALIDATION"}
assert all(x["review_status"] in allowed_review_statuses for x in review_rows)
assert any(x["review_status"]=="IMPLEMENTED_PENDING_VALIDATION" for x in review_rows)
assert all(x["review_status"]!="IMPLEMENTED_PENDING_VALIDATION" or
           "Patch " in x["review_basis"] for x in review_rows)
assert all(x["approval"].lower()=="false" for x in review_rows)

# A macro-only API with complete negative target evidence is excluded even
# when no direct prepared call remains and the pristine lexical count is nonzero.
macro_only=m.build_easymesh_api_subset(
 [],[],[],
 [{"component":"wappd","path":"wappd/crypto/evp.h","line":10,"api":"EVP_CIPHER_CTX_iv_noconst",
   "macro":"BLOCK_CIPHER_func_ofb","reachability_status":"EXCLUDED_WITH_EVIDENCE"},
  {"component":"wappd","path":"wappd/crypto/evp.h","line":20,"api":"EVP_CIPHER_CTX_iv_noconst",
   "macro":"BLOCK_CIPHER_func_cbc","reachability_status":"EXCLUDED_WITH_EVIDENCE"}],
 {"EVP_CIPHER_CTX_iv_noconst":{"observed_lexical_occurrences":"5","observed_components":"wappd",
   "migration_status":"UNREVIEWED","approval":"false"}},[])
assert len(macro_only)==1
assert macro_only[0]["prepared_call_count"]==0
assert macro_only[0]["macro_excluded"]==2
assert macro_only[0]["scope_status"]=="EXCLUDED_WITH_EVIDENCE"
assert macro_only[0]["needs_migration_review"] is False
# A single unknown macro reference must still fail closed.
macro_only_unknown=m.build_easymesh_api_subset(
 [],[],[],
 [{"component":"wappd","path":"wappd/crypto/evp.h","line":10,"api":"EVP_CIPHER_CTX_iv_noconst",
   "macro":"BLOCK_CIPHER_func_ofb","reachability_status":"UNKNOWN_FAIL_CLOSED"}],
 {"EVP_CIPHER_CTX_iv_noconst":{"observed_lexical_occurrences":"5","observed_components":"wappd",
   "migration_status":"UNREVIEWED","approval":"false"}},[])
assert macro_only_unknown[0]["scope_status"]=="UNKNOWN_FAIL_CLOSED"


# The 40-row EasyMesh semantic review, not the 68-row global baseline, is the
# authority for migration state. Exercise consistency, missing rows and forgery.
review_path=Path(__file__).with_name("openssl-40-active-api-semantic-review.csv")
with review_path.open(encoding="utf-8",newline="") as f:
 review_rows=list(csv.DictReader(f))
subset_rows=[]
for row in review_rows:
 api=m.normalize_api_name(row["api"])
 active=int(row["active_call_sites"]) if row["review_status"]=="REVIEWED_PENDING_IMPLEMENTATION" else 0
 subset_rows.append({"api":api,"active_call_sites":active})
assert m.validate_semantic_review(review_rows,subset_rows,git)==[]

missing_review=review_rows[:-1]
assert any("exactly 40 unique" in x for x in m.validate_semantic_review(missing_review,subset_rows,git))

inconsistent=[dict(x) for x in subset_rows]
implemented_api=next(m.normalize_api_name(x["api"]) for x in review_rows if x["review_status"]=="IMPLEMENTED_PENDING_VALIDATION")
next(x for x in inconsistent if x["api"]==implemented_api)["active_call_sites"]=1
assert any("status/source inconsistency" in x for x in m.validate_semantic_review(review_rows,inconsistent,git))

forged=[dict(x) for x in review_rows]
pending=next(x for x in forged if x["review_status"]=="REVIEWED_PENDING_IMPLEMENTATION")
pending["approval"]="true"
assert any("false approval" in x for x in m.validate_semantic_review(forged,subset_rows,git))

missing_evidence=[dict(x) for x in review_rows]
missing_evidence[0]["semantic_invariants"]=""
assert any("missing semantic_invariants" in x for x in m.validate_semantic_review(missing_evidence,subset_rows,git))

forged_approved=[dict(x) for x in review_rows]
candidate=next(x for x in forged_approved if x["review_status"]=="IMPLEMENTED_PENDING_VALIDATION")
candidate["review_status"]="MIGRATED"
candidate["approval"]="true"
candidate["review_basis"]="approved"
assert any("lacks current-SHA/run-attempt/regression evidence" in x for x in m.validate_semantic_review(forged_approved,subset_rows,git))


# Each live target callsite must be joined to its 40-API semantic decision.
sample_call={"component":"wappd","path":"wappd/dpp/dpp.c","line":123,"api":"EVP_PKEY_cmp",
             "reference_kind":"CALL_EXPRESSION","reachability_status":"ACTIVE","source_sha256":digest}
sample_review={"EVP_PKEY_cmp":{"review_status":"REVIEWED_PENDING_IMPLEMENTATION","approval":"false",
 "review_decision":"Migrate key comparison to EVP_PKEY_eq.",
 "semantic_invariants":"Preserve key equality semantics.",
 "review_basis":"source audit"}}
mapped=m.build_callsite_migration_map([sample_call],sample_review)
assert len(mapped)==1 and mapped[0]["path"]=="wappd/dpp/dpp.c"
assert mapped[0]["review_status"]=="REVIEWED_PENDING_IMPLEMENTATION"
assert mapped[0]["source_sha256"]==digest
assert m.build_callsite_migration_map([sample_call],{})[0]["review_status"]==""

print("PASS: exact target reachability excludes inactive APIs and declarations; active, unknown, missing, stale, unapproved and token-paste macro exclusions are handled fail-closed.")
