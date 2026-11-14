#!/bin/bash
# Runs every detections/*.kql against the Log Analytics workspace and fails on the first query the service rejects.
# This catches syntax errors, misspelled columns and missing tables before a rule is deployed.
# Usage: validate-kql.sh <resource-group> <workspace-name>     (needs an az login that can query the workspace)
set -u
rg="$1"; ws="$2"
sub=$(az account show --query id -o tsv)
url="https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws/api/query?api-version=2020-08-01"
failed=0
PY=$(command -v python || command -v python3)
for f in detections/*.kql; do
  body=$(mktemp)
  "$PY" - "$f" > "$body" <<'PY'
import json, sys
query = open(sys.argv[1], encoding="utf-8-sig").read().replace("__PIPELINE_OBJECT_ID__", "00000000-0000-0000-0000-000000000000")
print(json.dumps({"query": query, "timespan": "PT2H"}))
PY
  if out=$(az rest --method post --url "$url" --headers "Content-Type=application/json" --body "@$body" --query "length(Tables[0].Rows)" -o tsv 2>&1); then
    echo "ok    $f ($out rows)"
  else
    echo "::error file=$f::Query rejected: $(echo "$out" | head -3 | tr '\n' ' ')"
    failed=1
  fi
  rm -f "$body"
done
exit $failed
