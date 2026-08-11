#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

echo '== Go =='
(cd "$ROOT/services/gateway" && go test ./... && go vet ./...)

echo '== Python =='
PYTHONPATH="$ROOT/services/reputation" python3 -m unittest discover -s "$ROOT/services/reputation/tests" -p 'test_*.py'
python3 -m py_compile "$ROOT"/services/reputation/berry_reputation/*.py "$ROOT/tools/berryctl.py" "$ROOT/tools/har_summarize.py" "$ROOT/redteam/runner.py"

echo '== TypeScript / Node =='
(cd "$ROOT/packages/browser-sdk" && tsc -p tsconfig.json && npm test)

echo '== WebAssembly =='
node - "$ROOT/crates/probe-wasm/dist/probe.wasm" <<'JS'
const fs=require('fs');
(async()=>{ const file=process.argv[2]; const bytes=fs.readFileSync(file); const {instance}=await WebAssembly.instantiate(bytes,{}); if(typeof instance.exports.mix32 !== 'function') throw new Error('mix32 export missing'); console.log('probe.wasm OK', instance.exports.mix32(123)>>>0); })().catch(e=>{console.error(e);process.exit(1)});
JS

if command -v cargo >/dev/null 2>&1; then
  echo '== Rust =='
  (cd "$ROOT/services/risk-engine" && cargo test)
  (cd "$ROOT/crates/probe-wasm" && cargo test)
else
  echo '== Rust == SKIP (cargo not installed)'
fi
