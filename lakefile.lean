import Lake
open Lake DSL

package «lean-net» where
  version := v!"0.1.0"
  moreLinkArgs := run_io do
    let output ← IO.Process.output { cmd := "pkg-config", args := #["--libs", "zlib", "libbrotlienc", "libbrotlicommon"] }
    if output.exitCode != 0 then throw <| IO.userError "zlib and Brotli development libraries are required"
    let flags := (output.stdout.trimAscii.toString.splitOn " ").filter (· != "") |>.toArray
    if System.Platform.isWindows then
      -- Select import libraries without adding a broad MinGW CRT search path.
      let mut libraries := #["-lws2_32"]
      for (packageName, libraryName) in #[
          ("zlib", "libz.dll.a"), ("libbrotlienc", "libbrotlienc.dll.a"),
          ("libbrotlicommon", "libbrotlicommon.dll.a")] do
        let location ← IO.Process.output { cmd := "pkg-config", args := #["--variable=libdir", packageName] }
        if location.exitCode != 0 then throw <| IO.userError s!"cannot locate {packageName} import library"
        let path := System.FilePath.mk location.stdout.trimAscii.toString / libraryName
        unless ← path.pathExists do throw <| IO.userError s!"missing codec import library: {path}"
        libraries := libraries.push path.toString
      return libraries ++ flags.filter (fun flag => !flag.startsWith "-L" &&
        flag != "-lz" && flag != "-lbrotlienc" && flag != "-lbrotlicommon")
    if System.Platform.isOSX then
      let location ← IO.Process.output { cmd := "pkg-config", args := #["--variable=libdir", "zlib"] }
      if location.exitCode != 0 then throw <| IO.userError "cannot locate zlib library"
      let candidate := System.FilePath.mk location.stdout.trimAscii.toString / "libz.dylib"
      unless ← candidate.pathExists do
        throw <| IO.userError "Select an installed zlib with PKG_CONFIG_PATH; on macOS use Homebrew zlib's lib/pkgconfig directory"
      return flags.map (fun flag => if flag == "-lz" then candidate.toString else flag) ++ #["-pthread"]
    -- pkg-config omits system -L flags; Lean's bundled linker does not know
    -- the distribution's multiarch directories. Static Brotli also avoids
    -- importing the host shared library's newer versioned libm requirements.
    let mut libraries := #["-pthread"]
    for (packageName, libraryName) in #[
        ("zlib", "libz.so"), ("libbrotlienc", "libbrotlienc.a"),
        ("libbrotlicommon", "libbrotlicommon.a")] do
      let location ← IO.Process.output { cmd := "pkg-config", args := #["--variable=libdir", packageName] }
      if location.exitCode != 0 then throw <| IO.userError s!"cannot locate {packageName} library"
      let path := System.FilePath.mk location.stdout.trimAscii.toString / libraryName
      unless ← path.pathExists do throw <| IO.userError s!"missing codec library: {path}"
      libraries := libraries.push path.toString
    return libraries ++ flags.filter (fun flag =>
      flag != "-lz" && flag != "-lbrotlienc" && flag != "-lbrotlicommon") ++ #["-lm", "-lrt"]

@[default_target]
lean_lib LeanNet

@[default_target]
lean_exe «lean-net-echo» where
  root := `Main

lean_exe «lean-net-http1-perf» where
  root := `test.HTTP1Perf

lean_exe «lean-net-ffi-live» where
  root := `test.FFILive

lean_exe «lean-net-pool-lifetime-test» where
  root := `test.PoolLifetimeTest

@[default_target]
lean_exe «lean-net-http1» where
  root := `HTTPMain
  needs := #[`@/«lean-net-access-log-helper»]

lean_exe «lean-net-http1-fixture» where
  root := `test.HTTP1Fixture

lean_exe «lean-net-http2-fixture» where
  root := `test.HTTP2Fixture

lean_exe «lean-net-admission-fixture» where
  root := `test.AdmissionFixture

lean_exe «lean-net-gate-fixture» where
  root := `test.GateFixture

lean_exe «lean-net-gateway-pool-test» where
  root := `test.GatewayPoolTest

lean_exe «lean-net-gateway-engine-test» where
  root := `test.GatewayEngineTest

lean_exe «lean-net-gateway-h2-streaming-test» where
  root := `test.GatewayH2StreamingTest

lean_exe «lean-net-gateway-h1-streaming-test» where
  root := `test.GatewayH1StreamingTest

lean_exe «lean-net-event-ffi-test» where
  root := `test.EventFFITest

lean_exe «lean-net-transport-test» where
  root := `test.TransportSchedulerFixture

lean_exe «lean-net-reactor-native-test» where
  root := `test.ReactorNativeTest

lean_exe «lean-net-http1-reactor-fixture» where
  root := `test.HTTP1ReactorFixture

lean_exe «lean-net-http2-reactor-fixture» where
  root := `test.HTTP2ReactorFixture

lean_exe «lean-net-static-fixture» where
  root := `test.StaticReactorFixture

lean_exe «lean-net-protocol-fuzz» where
  root := `test.ProtocolFuzz
  moreLinkObjs := #[`@/«lean-net-fuzz-runtime»]

/-- Bound early Lean runtime threads before generated module initialization.
    This object belongs only to the serial protocol-fuzz executable. -/
target «lean-net-fuzz-runtime» pkg : System.FilePath := do
  let source ← inputTextFile (pkg.dir / "test" / "fuzz_runtime.c")
  let includeDir ← getLeanIncludeDir
  let compiler := if System.Platform.isWindows then "gcc" else "cc"
  buildO (pkg.buildDir / "c" / "fuzz_runtime.o") source
    #["-isystem", includeDir.toString]
    #["-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror"] compiler

lean_exe «lean-net-observability-fixture» where
  root := `test.ObservabilityReactorFixture
  needs := #[`@/«lean-net-access-log-helper»]

lean_exe «lean-net-process-metrics-test» where
  root := `test.ObservabilityProcessSamplerTest

lean_exe «lean-net-platform-info» where
  root := `test.PlatformInfo

lean_exe «lean-net-deferred-transport-fixture» where
  root := `test.DeferredTransportFixture
  needs := #[`@/«lean-net-access-log-helper»]

lean_exe «lean-net-keepalive-transport-fixture» where
  root := `test.KeepaliveTransportFixture
  needs := #[`@/«lean-net-access-log-helper»]

@[default_target]
target «lean-net-access-log-helper» pkg : System.FilePath := do
  let source ← inputTextFile (pkg.dir / "c" / "access_log_helper.c")
  let native ← inputTextFile (pkg.dir / "c" / "access_log.c")
  let header ← inputTextFile (pkg.dir / "c" / "access_log.h")
  let dependency := (source.zipWith (fun source _ => source) native).zipWith (fun source _ => source) header
  let output := pkg.buildDir / "bin" / (if System.Platform.isWindows then "lean-net-access-log-helper.exe" else "lean-net-access-log-helper")
  let compiler := if System.Platform.isWindows then "gcc" else "cc"
  buildFileAfterDep output dependency fun _ => do
    compileExe output (#["-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-O2", "-DOB_NO_LEAN_FFI",
      (pkg.dir / "c" / "access_log_helper.c").toString, (pkg.dir / "c" / "access_log.c").toString] ++
      (if System.Platform.isWindows || System.Platform.isOSX then #[] else #["-lrt"])) compiler

extern_lib socket_shim (pkg : NPackage __name__) := do
  let header ← inputTextFile (pkg.dir / "c" / "socket_shim.h")
  let reactorHeader ← inputTextFile (pkg.dir / "c" / "reactor.h")
  let ffiHeader ← inputTextFile (pkg.dir / "c" / "reactor_ffi.h")
  let gatewayResolve ← inputTextFile (pkg.dir / "c" / "gateway_resolve.h")
  let bridgeHeader ← inputTextFile (pkg.dir / "c" / "reactor_lean.h")
  let transportImpl ← inputTextFile (pkg.dir / "c" / "reactor_transport_impl.h")
  let fileHeader ← inputTextFile (pkg.dir / "c" / "reactor_file.h")
  let fileInternal ← inputTextFile (pkg.dir / "c" / "reactor_file_internal.h")
  let fileImpl ← inputTextFile (pkg.dir / "c" / "reactor_file_impl.h")
  let groupHeader ← inputTextFile (pkg.dir / "c" / "reactor_group.h")
  let cpuHeader ← inputTextFile (pkg.dir / "c" / "reactor_cpu.h")
  let affinityHeader ← inputTextFile (pkg.dir / "c" / "reactor_affinity.h")
  let groupFFI ← inputTextFile (pkg.dir / "c" / "reactor_group_ffi.h")
  let rateLimit ← inputTextFile (pkg.dir / "c" / "ratelimit.h")
  let counters ← inputTextFile (pkg.dir / "c" / "counters.h")
  let mut src ← inputTextFile (pkg.dir / "c" / "socket_shim.c")
  src := src.zipWith (fun source _ => source) header
  src := src.zipWith (fun source _ => source) reactorHeader
  src := src.zipWith (fun source _ => source) ffiHeader
  src := src.zipWith (fun source _ => source) gatewayResolve
  src := src.zipWith (fun source _ => source) bridgeHeader
  src := src.zipWith (fun source _ => source) fileHeader
  src := src.zipWith (fun source _ => source) groupHeader
  src := src.zipWith (fun source _ => source) groupFFI
  src := src.zipWith (fun source _ => source) rateLimit
  src := src.zipWith (fun source _ => source) counters
  if System.Platform.isWindows then
    let windows ← inputTextFile (pkg.dir / "c" / "socket_windows.c")
    src := src.zipWith (fun source _ => source) windows
    let errorHeader ← inputTextFile (pkg.dir / "c" / "windows_error.h")
    src := src.zipWith (fun source _ => source) errorHeader
    let windowsBridge ← inputTextFile (pkg.dir / "c" / "socket_windows_bridge.h")
    src := src.zipWith (fun source _ => source) windowsBridge
  let backend := if System.Platform.isWindows then "reactor_windows.c" else "reactor_posix.c"
  let native ← inputTextFile (pkg.dir / "c" / backend)
  let mut native := native.zipWith (fun source _ => source) reactorHeader
  native := native.zipWith (fun source _ => source) transportImpl
  native := native.zipWith (fun source _ => source) fileHeader
  native := native.zipWith (fun source _ => source) fileInternal
  native := native.zipWith (fun source _ => source) fileImpl
  if System.Platform.isWindows then
    let errorHeader ← inputTextFile (pkg.dir / "c" / "windows_error.h")
    native := native.zipWith (fun source _ => source) errorHeader
  let includeDir ← getLeanIncludeDir
  -- The bundled Windows clang sysroot lacks the Winsock SDK headers.
  -- Use the runner's complete MinGW toolchain for native sources.
  let compiler := if System.Platform.isWindows then "gcc" else "cc"
  let includes := #["-isystem", includeDir.toString]
  let options := #["-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror"]
  let obj ← buildO (pkg.buildDir / "c" / "socket_shim.o") src
    includes options compiler
  let nativeObj ← buildO (pkg.buildDir / "c" / "reactor.o") native
    includes options compiler
  let group ← inputTextFile (pkg.dir / "c" / "reactor_group.c")
  let group := (((group.zipWith (fun source _ => source) groupHeader).zipWith
    (fun source _ => source) reactorHeader).zipWith (fun source _ => source) cpuHeader).zipWith
    (fun source _ => source) affinityHeader
  let groupObj ← buildO (pkg.buildDir / "c" / "reactor_group.o") group
    includes options compiler
  let catalog ← inputTextFile (pkg.dir / "c" / "static_catalog.c")
  let catalogHeader ← inputTextFile (pkg.dir / "c" / "static_catalog.h")
  let catalog := ((catalog.zipWith (fun source _ => source) catalogHeader).zipWith
    (fun source _ => source) fileHeader).zipWith (fun source _ => source) reactorHeader
  let codecFlags ← IO.Process.output { cmd := "pkg-config", args := #["--cflags", "zlib", "libbrotlienc", "libbrotlicommon"] }
  if codecFlags.exitCode != 0 then error "cannot locate zlib and Brotli headers"
  let codecIncludes := (codecFlags.stdout.trimAscii.toString.splitOn " ").filter (· != "") |>.toArray
  let catalogObj ← buildO (pkg.buildDir / "c" / "static_catalog.o") catalog
    (includes ++ codecIncludes) options compiler
  let logger ← inputTextFile (pkg.dir / "c" / "access_log.c")
  let loggerHeader ← inputTextFile (pkg.dir / "c" / "access_log.h")
  let logger := logger.zipWith (fun source _ => source) loggerHeader
  let loggerObj ← buildO (pkg.buildDir / "c" / "access_log.o") logger includes options compiler
  buildStaticLib (pkg.staticLibDir / nameToStaticLib "socket_shim") #[obj, nativeObj, groupObj, catalogObj, loggerObj]
