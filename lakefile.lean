import Lake
open Lake DSL

package «lean-net» where
  version := v!"0.1.0"
  moreLinkArgs := if System.Platform.isWindows then #["-lws2_32"] else #[]

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

lean_exe «lean-net-http1-fixture» where
  root := `test.HTTP1Fixture

lean_exe «lean-net-http2-fixture» where
  root := `test.HTTP2Fixture

lean_exe «lean-net-event-ffi-test» where
  root := `test.EventFFITest

lean_exe «lean-net-transport-test» where
  root := `test.TransportSchedulerFixture

lean_exe «lean-net-reactor-native-test» where
  root := `test.ReactorNativeTest

lean_exe «lean-net-http1-reactor-fixture» where
  root := `test.HTTP1ReactorFixture

extern_lib socket_shim (pkg : NPackage __name__) := do
  let header ← inputTextFile (pkg.dir / "c" / "socket_shim.h")
  let reactorHeader ← inputTextFile (pkg.dir / "c" / "reactor.h")
  let ffiHeader ← inputTextFile (pkg.dir / "c" / "reactor_ffi.h")
  let groupHeader ← inputTextFile (pkg.dir / "c" / "reactor_group.h")
  let groupFFI ← inputTextFile (pkg.dir / "c" / "reactor_group_ffi.h")
  let mut src ← inputTextFile (pkg.dir / "c" / "socket_shim.c")
  src := src.zipWith (fun source _ => source) header
  src := src.zipWith (fun source _ => source) reactorHeader
  src := src.zipWith (fun source _ => source) ffiHeader
  src := src.zipWith (fun source _ => source) groupHeader
  src := src.zipWith (fun source _ => source) groupFFI
  if System.Platform.isWindows then
    let windows ← inputTextFile (pkg.dir / "c" / "socket_windows.c")
    src := src.zipWith (fun source _ => source) windows
    let errorHeader ← inputTextFile (pkg.dir / "c" / "windows_error.h")
    src := src.zipWith (fun source _ => source) errorHeader
  let backend := if System.Platform.isWindows then "reactor_windows.c" else "reactor_posix.c"
  let native ← inputTextFile (pkg.dir / "c" / backend)
  let mut native := native.zipWith (fun source _ => source) reactorHeader
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
  let group := (group.zipWith (fun source _ => source) groupHeader).zipWith (fun source _ => source) reactorHeader
  let groupObj ← buildO (pkg.buildDir / "c" / "reactor_group.o") group
    includes options compiler
  buildStaticLib (pkg.staticLibDir / nameToStaticLib "socket_shim") #[obj, nativeObj, groupObj]
