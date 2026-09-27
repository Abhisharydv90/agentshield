import re
import json

COMMENT_RE = re.compile(r"(/\*.*?\*/|--[^\n]*|#[^\n]*)", re.DOTALL)
B64_RE = re.compile(r"base64[:=]\s*([A-Za-z0-9+/=]{40,})", re.I)

def normalize_tool_call(raw: dict) -> dict:
    sql = raw.get("args", {}).get("query", "")
    
    flags = {
        "contains_comment_bypass": bool(COMMENT_RE.search(sql)),
        "contains_compound_statement": ";" in sql.strip().rstrip(";"),
        "contains_encoded_payload": bool(B64_RE.search(json.dumps(raw))),
    }
    
    clean_sql = COMMENT_RE.sub("", sql).strip().rstrip(";")
    
    op = "unknown"
    sql_lower = clean_sql.lower()
    if sql_lower.startswith(("select", "show", "describe")):
        op = "read"
    elif sql_lower.startswith(("drop", "truncate", "delete")):
        op = "delete"
    elif sql_lower.startswith(("insert", "update", "alter")):
        op = "write"
    elif sql_lower.startswith(("exec", "call", "xp_")):
        op = "execute"

    return {
        "tool_name": raw.get("name", "unknown"),
        "op": op,
        "target": raw.get("args", {}).get("table") or raw.get("args", {}).get("host"),
        "args_normalized": {"sql": clean_sql},
        **flags,
    }