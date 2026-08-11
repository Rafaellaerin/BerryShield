.PHONY: verify go-test py-test sdk-build sdk-test rust-test demo
verify:
	./scripts/verify.sh

go-test:
	cd services/gateway && go test ./...

py-test:
	PYTHONPATH=services/reputation python3 -m unittest discover -s services/reputation/tests -p 'test_*.py'

sdk-build:
	cd packages/browser-sdk && tsc -p tsconfig.json

sdk-test: sdk-build
	cd packages/browser-sdk && npm test

rust-test:
	cd services/risk-engine && cargo test
	cd crates/probe-wasm && cargo test

demo:
	python3 -m http.server 3000
