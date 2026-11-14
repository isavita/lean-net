# Linux codec and Windows cold-start diagnosis

Source `995751118bbe93f8a9c8946360b5842847985fe4` is **not accepted**.
Linux and macOS Native passed; macOS and Windows TLS passed, including the
static-file suites. Two separate issues remain in this preserved candidate:

- Linux TLS and full regression reach TLS executable linking, where explicitly
  selected host OpenSSL shared libraries need newer glibc symbols than Lean's
  link environment. The next candidate restores OpenSSL's established
  pkg-config lookup while retaining explicit codec paths and static Brotli.
- Windows Native's injected startup-failure test captures 57 process handles
  before preparation and 64 after cleanup. All four catalog file handles close.
  The security-descriptor conversion creates the seven new non-File handles:
  two Events, three ETW registrations, one Thread and one ALPC port. The next
  test initializes that exact API before its baseline, then demands flat
  process counts and four-created/four-closed ownership in each of 1,000
  injected failures. Actual Windows validation remains necessary.

The `ci/` directory retains complete run/job/step status snapshots and raw
failed-job logs, including the handle types and per-operation counts. No
production C or protocol changes were needed for the Windows finding.
