import Lake
open Lake DSL

package «lean-net-tls» where
  moreLinkArgs := run_io do
    let version ← IO.Process.output { cmd := "pkg-config", args := #["--atleast-version=1.1.1", "openssl"] }
    if version.exitCode != 0 then throw <| IO.userError "OpenSSL 1.1.1 or newer is required"
    let output ← IO.Process.output { cmd := "pkg-config", args := #["--libs", "openssl"] }
    if output.exitCode != 0 then throw <| IO.userError "pkg-config --libs openssl failed"
    return (output.stdout.trimAscii.toString.splitOn " ").filter (· != "") |>.toArray

require «lean-net» from "../"

@[default_target]
lean_lib LeanNetTLS

extern_lib tls_shim (pkg : NPackage __name__) := do
  let src ← inputTextFile (pkg.dir / "c" / "tls_shim.c")
  let includeDir ← getLeanIncludeDir
  let output ← IO.Process.output { cmd := "pkg-config", args := #["--cflags", "openssl"] }
  if output.exitCode != 0 then error "pkg-config --cflags openssl failed"
  let flags := (output.stdout.trimAscii.toString.splitOn " ").filter (· != "") |>.toArray
  let obj ← buildO (pkg.buildDir / "c" / "tls_shim.o") src
    (#["-isystem", includeDir.toString] ++ flags) #["-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror"]
  buildStaticLib (pkg.staticLibDir / nameToStaticLib "tls_shim") #[obj]

lean_exe «lean-net-tls» where
  root := `Main

lean_exe «lean-net-tls-fixture» where
  root := `test.TLSFixture

lean_exe «lean-net-tls-interruptible-test» where
  root := `test.TLSInterruptibleTest
