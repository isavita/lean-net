# Tests

The GitHub Actions matrix builds and tests the core and TLS packages on Linux, macOS and Windows. Run focused suites locally after building their fixtures:

```sh
lake build
lake build lean-net-gateway-pool-test lean-net-gateway-engine-test
lake env lean --run test/HTTP1MachineTest.lean
lake env lean --run test/HTTP2ConnectionV2Test.lean
lake env lean --run test/GateTest.lean
python3 test/test_http1_reactor.py -v
python3 test/test_http2_reactor.py -v
python3 test/test_gateway_runtime.py -v
python3 test/test_websocket.py -v
python3 test/soak.py --count 10000
```

HTTP/2 Python tests use `test/requirements-http2.txt`. TLS tests require OpenSSL and `lake -d tls build lean-net-tls`:

```sh
python3 -m pip install -r test/requirements-http2.txt
python3 tls/test/test_tls_reactor.py -v
python3 tls/test/test_tls_gateway_e2e.py -v
python3 tls/test/test_tls_production.py -v
```

The deterministic protocol fuzz runner has a short profile:

```sh
lake build lean-net-protocol-fuzz
python3 test/fuzz_protocols.py --profile short --output /tmp/lean-net-fuzz-short
```

For the separate full-duration HTTP/2 capacity and resource soak, build both public executables and use `test/soak24.py --config test/soak24.example.json --source-sha COMMIT --output REPORT_DIRECTORY`. `--smoke-seconds N` checks orchestration and cannot pass the 24-hour acceptance gate. The controller records its JSON result and raw metrics in the output directory. See `python3 test/soak24.py --help` for options.
