import Lake
open Lake DSL

package «lean-net» where
  version := v!"0.1.0"

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

extern_lib socket_shim (pkg : NPackage __name__) := do
  let src ← inputTextFile (pkg.dir / "c" / "socket_shim.c")
  let header ← inputTextFile (pkg.dir / "c" / "socket_shim.h")
  let src := src.zipWith (fun source _ => source) header
  let includeDir ← getLeanIncludeDir
  let obj ← buildO (pkg.buildDir / "c" / "socket_shim.o") src
    #["-isystem", includeDir.toString] #["-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror"]
  buildStaticLib (pkg.staticLibDir / nameToStaticLib "socket_shim") #[obj]
