# lean-net
```text
lean-net/
├── lakefile.toml              # Package manifest (TOML preferred for static config)
├── lean-toolchain             # Pin the toolchain, commit this
├── README.md
├── .gitignore                 # .lake/
├── c/                         # C FFI shim — not Lean, not part of the library tree
│   ├── socket_shim.c
│   └── socket_shim.h          # Optional: keep the C contract visible
├── LeanNet.lean               # Root hub: imports everything public
├── LeanNet/
│   ├── FFI/
│   │   ├── Raw.lean           # extern declarations + IO wrappers for raw syscalls
│   │   └── Errno.lean         # errno → Lean error mapping
│   ├── Socket/
│   │   ├── Handle.lean        # opaque socket handle type + close semantics
│   │   ├── Address.lean       # host/port representation, IPv4/IPv6
│   │   └── Buffer.lean        # ByteArray helpers for recv/send (optional this phase)
│   ├── TCP/
│   │   ├── Listener.lean      # bind/listen/accept lifecycle
│   │   └── Connection.lean    # recv/send on a connected socket
│   └── Echo/
│       └── Server.lean        # the echo loop logic — library-level, testable
├── Main.lean                  # Executable entry point: parses args, starts server
└── test/
    └── LeanNetTest.lean       # Test driver target
```
