import Lake
open Lake DSL

package «lean-net-tls» where
  version := v!"0.1.1"
  description := "TLS, mTLS, SNI and verified HTTPS upstreams for lean-net"
  keywords := #["networking", "http", "http2", "tls", "mtls", "openssl", "ffi"]
  homepage := "https://isavita.github.io/lean-net/LeanNetTLS.html"
  license := "Apache-2.0"
  licenseFiles := #["../LICENSE", "../NOTICE"]
  moreLinkArgs := run_io do
    let version ← IO.Process.output { cmd := "pkg-config", args := #["--atleast-version=1.1.1", "openssl"] }
    if version.exitCode != 0 then throw <| IO.userError "OpenSSL 1.1.1 or newer is required"
    let output ← IO.Process.output { cmd := "pkg-config", args := #["--libs", "openssl", "zlib", "libbrotlienc", "libbrotlicommon"] }
    if output.exitCode != 0 then throw <| IO.userError "pkg-config could not locate TLS and file-codec libraries"
    let flags := (output.stdout.trimAscii.toString.splitOn " ").filter (· != "") |>.toArray
    if System.Platform.isWindows then
      -- A broad MSYS2 -L path also overrides Lean's matching MinGW CRT archives.
      -- Select only OpenSSL's DLL import libraries, retaining Lean's CRT order.
      let location ← IO.Process.output { cmd := "pkg-config", args := #["--variable=libdir", "openssl"] }
      if location.exitCode != 0 || location.stdout.trimAscii.toString.isEmpty then
        throw <| IO.userError "pkg-config could not locate the OpenSSL import libraries"
      let directory := System.FilePath.mk location.stdout.trimAscii.toString
      let mut libraries : Array String := #["-lws2_32"]
      for name in #["libssl.dll.a", "libcrypto.dll.a"] do
        let path := directory / name
        unless ← path.pathExists do
          throw <| IO.userError s!"missing OpenSSL DLL import library: {path}"
        libraries := libraries.push path.toString
      for (packageName, libraryName) in #[
          ("zlib", "libz.dll.a"), ("libbrotlienc", "libbrotlienc.dll.a"),
          ("libbrotlicommon", "libbrotlicommon.dll.a")] do
        let location ← IO.Process.output { cmd := "pkg-config", args := #["--variable=libdir", packageName] }
        if location.exitCode != 0 then throw <| IO.userError s!"cannot locate {packageName} import library"
        let path := System.FilePath.mk location.stdout.trimAscii.toString / libraryName
        unless ← path.pathExists do throw <| IO.userError s!"missing codec import library: {path}"
        libraries := libraries.push path.toString
      return libraries ++ flags.filter (fun flag =>
        !flag.startsWith "-L" && flag != "-lssl" && flag != "-lcrypto" &&
        flag != "-lz" && flag != "-lbrotlienc" && flag != "-lbrotlicommon")
    if System.Platform.isOSX then
      let location ← IO.Process.output { cmd := "pkg-config", args := #["--variable=libdir", "zlib"] }
      if location.exitCode != 0 then throw <| IO.userError "cannot locate zlib library"
      let library := System.FilePath.mk location.stdout.trimAscii.toString / "libz.dylib"
      unless ← library.pathExists do
        throw <| IO.userError "Select macOS zlib's lib/pkgconfig directory in PKG_CONFIG_PATH"
      return flags.map (fun flag => if flag == "-lz" then library.toString else flag) ++ #["-pthread"]
    -- Use explicit multiarch paths and static Brotli, whose unversioned math
    -- references can resolve against Lean's matching bundled libm. Retain
    -- OpenSSL's established pkg-config lookup and select only codecs here.
    let mut libraries := #["-pthread"]
    for (packageName, libraryName) in #[
        ("zlib", "libz.so"), ("libbrotlienc", "libbrotlienc.a"),
        ("libbrotlicommon", "libbrotlicommon.a")] do
      let location ← IO.Process.output { cmd := "pkg-config", args := #["--variable=libdir", packageName] }
      if location.exitCode != 0 then throw <| IO.userError s!"cannot locate {packageName} library"
      let path := System.FilePath.mk location.stdout.trimAscii.toString / libraryName
      unless ← path.pathExists do throw <| IO.userError s!"missing native library: {path}"
      libraries := libraries.push path.toString
    return libraries ++ flags.filter (fun flag =>
      flag != "-lz" &&
      flag != "-lbrotlienc" && flag != "-lbrotlicommon") ++ #["-lm", "-lrt"]

require «lean-net» from "../"

@[default_target]
lean_lib LeanNetTLS

extern_lib tls_shim (pkg : NPackage __name__) := do
  let mut src ← inputTextFile (pkg.dir / "c" / "tls_shim.c")
  for path in #[pkg.dir / ".." / "c" / "socket_windows_bridge.h",
      pkg.dir / ".." / "c" / "windows_error.h"] do
    let header ← inputTextFile path
    src := src.zipWith (fun source _ => source) header
  let includeDir ← getLeanIncludeDir
  let output ← IO.Process.output { cmd := "pkg-config", args := #["--cflags", "openssl"] }
  if output.exitCode != 0 then error "pkg-config --cflags openssl failed"
  let flags := (output.stdout.trimAscii.toString.splitOn " ").filter (· != "") |>.toArray
  let compiler := if System.Platform.isWindows then "gcc" else "cc"
  let obj ← buildO (pkg.buildDir / "c" / "tls_shim.o") src
    (#["-isystem", includeDir.toString] ++ flags) #["-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror"] compiler
  let mut worker ← inputTextFile (pkg.dir / "c" / "tls_worker.c")
  for path in #[pkg.dir / "c" / "tls_worker.h", pkg.dir / "c" / "tls_reload.h", pkg.dir / ".." / "c" / "reactor.h",
      pkg.dir / ".." / "c" / "reactor_lean.h", pkg.dir / ".." / "c" / "reactor_file.h",
      pkg.dir / ".." / "c" / "reactor_file_internal.h", pkg.dir / ".." / "c" / "reactor_file_impl.h"] do
    let header ← inputTextFile path
    worker := worker.zipWith (fun source _ => source) header
  let threadFlags := if System.Platform.isWindows then #[] else #["-pthread"]
  let workerObj ← buildO (pkg.buildDir / "c" / "tls_worker.o") worker
    (#["-isystem", includeDir.toString] ++ flags)
    (#["-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror"] ++ threadFlags) compiler
  let gateway ← inputTextFile (pkg.dir / "c" / "tls_gateway.c")
  let gatewayObj ← buildO (pkg.buildDir / "c" / "tls_gateway.o") gateway
    (#["-isystem", includeDir.toString] ++ flags)
    #["-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror"] compiler
  buildStaticLib (pkg.staticLibDir / nameToStaticLib "tls_shim") #[obj, workerObj, gatewayObj]

lean_exe «lean-net-tls» where
  root := `Main
  needs := #[`@/«lean-net-access-log-helper»]

target «lean-net-access-log-helper» pkg : System.FilePath := do
  let directory := pkg.dir / ".." / "c"
  let source ← inputTextFile (directory / "access_log_helper.c")
  let native ← inputTextFile (directory / "access_log.c")
  let header ← inputTextFile (directory / "access_log.h")
  let dependency := (source.zipWith (fun source _ => source) native).zipWith (fun source _ => source) header
  let output := pkg.buildDir / "bin" / (if System.Platform.isWindows then "lean-net-access-log-helper.exe" else "lean-net-access-log-helper")
  let compiler := if System.Platform.isWindows then "gcc" else "cc"
  buildFileAfterDep output dependency fun _ => do
    compileExe output (#["-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-O2", "-DOB_NO_LEAN_FFI",
      (directory / "access_log_helper.c").toString, (directory / "access_log.c").toString] ++
      (if System.Platform.isWindows || System.Platform.isOSX then #[] else #["-lrt"])) compiler

lean_exe «lean-net-tls-fixture» where
  root := `test.TLSFixture

lean_exe «lean-net-tls-interruptible-test» where
  root := `test.TLSInterruptibleTest

lean_exe «lean-net-tls-gateway-test» where
  root := `test.TLSGatewayTest

lean_exe «lean-net-tls-reactor-fixture» where
  root := `test.TLSReactorFixture

lean_exe «lean-net-tls-static-fixture» where
  root := `test.TLSStaticFixture

lean_exe «lean-net-tls-reload-fixture» where
  root := `test.TLSReloadFixture

lean_exe «lean-net-tls-worker-lifetime-test» where
  root := `test.TLSWorkerLifetimeTest

lean_exe «lean-net-tls-admission-fixture» where
  root := `test.TLSAdmissionFixture
