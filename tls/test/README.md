# TLS tests

Build the TLS package and run its native reactor and public-server suites from the repository root:

```sh
python3 -m pip install -r test/requirements-http2.txt
lake build lean-net-http1
lake -d tls build lean-net-tls lean-net-tls-reactor-fixture lean-net-tls-admission-fixture
python3 tls/test/test_tls_reactor.py -v
python3 tls/test/test_tls_gateway_e2e.py -v
python3 tls/test/test_tls_production.py -v
```

The tests generate their own CA and host certificates. `LEAN_NET_TEST_OPENSSL` and `LEAN_NET_TEST_CURL` select client executables; `LEAN_NET_TLS_REACTOR_BIN` selects a fixture binary. `LEAN_NET_TLS_CYCLES=20` shortens the 1,000-connection resource test for local diagnostics.

To run the pinned full `testssl.sh` fixture scan:

```sh
git clone --depth 1 --branch v3.2.5 https://github.com/testssl/testssl.sh.git /tmp/lean-net-testssl-v3.2.5
python3 tls/test/run_testssl.py --testssl /tmp/lean-net-testssl-v3.2.5 --output /tmp/lean-net-testssl-report
```

The scanner report contains its grade, raw logs, commands and fixture metadata. Use a new output directory for each run.
