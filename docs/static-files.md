# Static files

`LeanNet.HTTP.Static.serveRoot` serves a prepared directory through HTTP/1.0,
HTTP/1.1 and prior-knowledge HTTP/2. The optional TLS package provides
`LeanNetTLS.ReactorServer.serveStaticRoot` for ALPN-selected HTTP/2 and HTTP/1.1.
Both use the native reactor controller and partition the client limit across
workers. Static-file acceptance and the remaining production gates are tracked
in the [roadmap](production-roadmap.md).

The public executables accept these forms:

```sh
lake build lean-net-http1
.lake/build/bin/lean-net-http1 8080 --static ./public --static-memory 8

lake -d tls build lean-net-tls
tls/.lake/build/bin/lean-net-tls ./chain.pem ./key.pem 8443 --static ./public --static-memory 8
curl --cacert ./ca.pem --http2 https://localhost:8443/asset.bin
```

Both executables bind `127.0.0.1`. The optional port defaults to 8080 for
cleartext and 8443 for TLS. `--static-memory` requires `--static`, accepts
1–1024 MiB, and defaults to 8 MiB. It sets the maximum original file size,
packed-file size and resident-byte budget together. `--enable-push` remains
available, but the static handlers do not propose pushes.

The root package now requires `pkg-config`, zlib and Brotli development
libraries; the codec package names are `zlib`, `libbrotlienc` and
`libbrotlicommon`. TLS additionally requires OpenSSL 1.1.1 or newer. See the
[root build instructions](../README.md#build-and-test) and
[TLS setup](../tls/README.md) for platform dependencies.

The library entry points accept separate catalog, HTTP and TLS configuration:

```lean
import LeanNet.HTTP.Static

def main : IO Unit :=
  LeanNet.HTTP.Static.serveRoot (System.FilePath.mk "./public")
```

```lean
import LeanNetTLS.ReactorServer

def main : IO Unit :=
  LeanNetTLS.ReactorServer.serveStaticRoot (System.FilePath.mk "./public")
    { certificateChain := "./chain.pem", privateKey := "./key.pem" }
```

`serveRoot root catalogConfig httpConfig host port` and
`serveStaticRoot root tlsConfig catalogConfig httpConfig host port` expose the
remaining arguments. `HTTP.ReactorServerConfig` controls workers, admission,
timeouts and protocol limits. The default worker count is the available core
count, capped by the global client limit.

The server prepares everything before listening. It opens a root directory
anchor, enumerates each directory through that anchor with a native entry
bound, and opens child components without following symbolic links or Windows
reparse points. Links and special files are omitted, but still count toward
the traversal bound. Keep the input tree stable during preparation; startup is
not an atomic filesystem snapshot.

Original files, generated directory pages, and retained gzip/Brotli variants
are copied into one private packed file. The builder closes all writable
aliases before publishing a read-only mapping. The mapping is shared across
workers; each worker imports one native file registration. Serving uses cached
metadata and range identities, with no request-time path lookup, directory
enumeration, file open or stat. Editing, truncating or deleting originals after
startup leaves the served bytes unchanged. Restart with a new catalog to
publish changes.

`HTTP.Static.Catalog.Config` and its `File.BuilderConfig` have these defaults:

| Setting | Default |
| --- | ---: |
| `residentBytes` | 8 MiB |
| `builder.maxFileBytes` / `builder.maxPackBytes` | 8 MiB each |
| `builder.maxEntries` | 4,096 |
| `maxDepth` | 32 |
| `maxListingBytes` | 256 KiB |
| `builder.minCompressBytes` | 128 bytes |
| `builder.gzipLevel` / `builder.brotliQuality` | 6 / 5 |
| `builder.stepBytes` / `builder.startupTimeoutMs` | 64 KiB / 120,000 ms |
| `adjustWorkingSet` / `directoryIndex` | `true` / `true` |
| `indexNames` | `index.html`, then `index.htm` |

The resident charge is the whole packed file rounded up to the OS page size.
Budget for identity bytes, compressed variants and generated listings together;
the pack limit also bounds temporary compression output. Compression runs only
at startup, and a variant is retained only when smaller than the original.
Raising `residentBytes` alone does not raise the builder's independent file or
pack limits. HTTP has separate logical file limits:
`server.maxFileResponseBytes` defaults to 1 GiB and `maxQueuedFileBytes` to
4 GiB per connection. Byte-array output has its own limit.

Publication eagerly maps and locks all served pages using `mlock` on Unix or
`VirtualLock` on Windows. Startup fails if locking or the page-rounded budget
cannot be satisfied; a larger configured budget does not override the Unix
locked-memory resource limit. With `adjustWorkingSet := true`, Windows first
requests a bounded increase of its process working-set minimum. Set it to
`false` when the application manages that policy itself; locking remains
mandatory. Windows also requires filesystem support for POSIX-style removal
of the private temporary pack while its handles remain open. Unsupported
systems fail startup rather than expose a temporary catalog entry. Pinning
avoids cold data-page faults; it does not make kernel I/O calls wait-free.

GET and HEAD select identity, gzip or Brotli according to `Accept-Encoding`.
Missing or empty fields select identity. Explicit weights compete, with
Brotli, gzip, then identity breaking ties; implicit identity is a fallback.
An excluded representation is never selected; the server returns 406 when no
available representation is acceptable. Replies use `Vary: Accept-Encoding` and strong
SHA-256-based ETags for the actual encoded bytes. The default cache policy is
`public, max-age=0, must-revalidate`.

`If-Match` and `If-Unmodified-Since` run before `If-None-Match` and
`If-Modified-Since`. `If-None-Match` takes precedence over modification dates
and accepts weak comparisons and `*`; 304 responses omit both body and
Content-Length. HEAD reports the selected GET representation's full length
without sending file data. Other methods receive 405.

Single closed, open-ended and suffix byte ranges select 206. Valid
unsatisfiable ranges return 416 with `Content-Range: bytes */length`; malformed,
multiple or unknown-unit ranges are ignored. Ranges address the selected
encoded representation. `If-Range` accepts an exact strong ETag, or an exact
Last-Modified date considered strong at preparation time: the file must be at
least 60 seconds old. Weak tags and recent timestamps select the full response.
Range is applied only to GET.

Directories prefer configured index files. Without one, `directoryIndex :=
true` generates a bounded HTML page with escaped labels and percent-encoded
UTF-8 links; disabling it produces 403 for such directories. A directory URL
missing its trailing slash redirects with 308 and preserves the query. Paths
are decoded once. Invalid UTF-8, traversal components, encoded separators,
backslashes, control characters, trailing dots/spaces and portable Windows
device names are rejected. Discovered filenames must satisfy the same portable
policy or preparation fails.

Cleartext file output uses Linux `sendfile`, macOS `sendfile`, or Windows
`TransmitFile`, with partial progress and cancellation tracked in the same
FIFO as ordinary writes. TLS file output runs on the dedicated TLS thread.
Linux uses a preallocated pipe and real `splice` before copying bounded chunks
into OpenSSL input; unsupported or unavailable splice paths copy the pinned
mapping. macOS and Windows copy that mapping directly. TLS encryption still
requires the user-space copy: this is not zero-copy TLS. File references remain
pinned until their encrypted wire fences complete, or cancellation and worker
join make release safe.

For custom integration, `Catalog.withCatalog` brackets preparation and source
ownership; `catalog.bind reactor` registers the pack before that worker's first
poll, and `bound.handlers` supplies its independently owned HTTP handlers.
`bound.plan request context` exposes pure request selection. Keep the catalog
bracket outside every reactor and TLS worker bracket. Stop and join workers,
drain native cancellation, destroy reactor registrations, then release the
catalog. `FileRegion` is borrowed metadata, not an owning file handle; native
owner IDs, generations and range bounds validate every submission. Do not
release catalog registrations merely because a handler exits while IOCP work
may still be pending. The high-level serving entry points arrange this order
without finalizers.

Missing roots, unsupported names, excessive entries/depth/listings, changed
source files, codec failures, exhausted preparation time, and lock/budget
failures abort preparation before listening. After response headers have been
sent, a file I/O failure closes that connection so later bytes cannot be
misinterpreted as part of its body.
