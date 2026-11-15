# Static files

`LeanNet.HTTP.Static.serveRoot` serves one prepared directory over HTTP/1.x and h2c. `LeanNetTLS.ReactorServer.serveStaticRoot` serves it over TLS and ALPN. The directory is prepared before listening; replace the catalog or restart to publish changed files.

```lean
import LeanNet

def main : IO Unit :=
  LeanNet.HTTP.Static.serveRoot (System.FilePath.mk "./public")
    { residentBytes := 32 * 1024 * 1024,
      builder := { maxPackBytes := 32 * 1024 * 1024,
                   maxFileBytes := 32 * 1024 * 1024 } }
    { server := { maxClients := 128 } }
    "127.0.0.1" 8080
```

`serveRoot root catalogConfig httpConfig host port` and the TLS `serveStaticRoot root tlsConfig catalogConfig httpConfig host port` accept the same catalog configuration. Both supplied executables also accept `--static DIR --static-memory MiB`; the latter defaults to 8 MiB and sets the resident, pack and per-file budgets together.

| `HTTP.Static.Catalog.Config` field | Default | Use |
| --- | ---: | --- |
| `residentBytes` | 8 MiB | Packed, resident catalog budget |
| `builder.maxPackBytes`, `maxFileBytes` | 8 MiB each | Packed and individual file limits |
| `builder.maxEntries` | 4,096 | Input entry limit |
| `builder.minCompressBytes` | 128 | Minimum size for generated gzip/Brotli variants |
| `builder.gzipLevel`, `brotliQuality` | 6; 5 | Compression levels |
| `builder.startupTimeoutMs` | 120,000 | Preparation deadline |
| `maxDepth`, `maxListingBytes` | 32; 256 KiB | Directory traversal and generated listing bounds |
| `directoryIndex`, `indexNames` | `true`; `index.html`, `index.htm` | Directory index behavior |
| `selection.cacheControl` | `public, max-age=0, must-revalidate` | Response cache policy |

Budget for originals, generated pages and compressed variants together. The packed catalog is locked in memory; startup fails when its budget or the OS locked-memory limit is insufficient. The root must remain stable during preparation. Symbolic links and special files are excluded.

GET and HEAD support gzip/Brotli negotiation, ETags, Last-Modified, conditional requests and single byte ranges. Directories use an index file or a generated listing; set `directoryIndex := false` to return 403 when no index exists. Cleartext file responses use platform file-transfer calls; TLS responses are encrypted by the TLS worker.

For custom worker setup, use `HTTP.Static.Catalog.withCatalog root config fun catalog => ...`, then `catalog.bind reactor` once per worker and `bound.handlers` for request handling. Keep the catalog bracket outside the worker brackets.
