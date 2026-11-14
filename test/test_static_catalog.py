#!/usr/bin/env python3
"""Actual packed startup codec/publication tests, with native lifetime sanitizers."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
import gzip

ROOT = Path(__file__).resolve().parents[1]


class StaticCatalogNative(unittest.TestCase):
    def test_packed_codecs_hashes_limits_and_lifetimes(self):
        compiler = os.environ.get("CC", "gcc" if sys.platform == "win32" else "cc")
        flags = shlex.split(subprocess.check_output(
            ["pkg-config", "--cflags", "--libs", "zlib", "libbrotlienc", "libbrotlidec"], text=True))
        with tempfile.TemporaryDirectory(prefix="lean-net-static-native-") as temporary:
            directory = Path(temporary); assets = directory / "assets"; assets.mkdir(); (assets / "sub").mkdir()
            expected = bytes(range(256)) * 4096
            (assets / "data.bin").write_bytes(expected); (assets / "unicode-λ.txt").write_bytes(b"unicode")
            (assets / "mutable.bin").write_bytes(expected)
            overflow = assets / "overflow"; overflow.mkdir()
            for index in range(20):
                (overflow / f"entry-{index}").write_bytes(b"")
            if sys.platform != "win32":
                (directory / "outside").write_bytes(b"must not enter catalog")
                (assets / "outside-link").symlink_to(directory / "outside")
                (assets / "directory-link").symlink_to(directory, target_is_directory=True)
                skipped = assets / "skipped"; skipped.mkdir()
                for index in range(20):
                    (overflow / f"link-{index}").symlink_to(directory / "outside")
                    (skipped / f"link-{index}").symlink_to(directory / "outside")
            binary = directory / ("catalog.exe" if sys.platform == "win32" else "catalog")
            command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-O1", "-g",
                       str(ROOT / "test/static_catalog_native.c"), "-o", str(binary), *flags]
            if sys.platform != "win32":
                command += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            else:
                command += ["-ladvapi32"]
            subprocess.run(command, check=True, capture_output=True, timeout=60)
            env = os.environ.copy()
            if sys.platform == "win32":
                env["TMP"] = env["TEMP"] = str(assets)
            else:
                env["TMPDIR"] = str(assets)
            # Apple's ASan runtime does not implement LeakSanitizer. Linux
            # retains LSan; all platforms check 1,000 handle/pin lifetimes.
            env["ASAN_OPTIONS"] = ("detect_leaks=0" if sys.platform == "darwin" else "detect_leaks=1") + ":halt_on_error=1"
            result = subprocess.run([str(binary), str(assets), str(directory)], env=env,
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["cycles"], 1000); self.assertLessEqual(report["handles_after"], report["handles_before"])
            for variant in report["variants"]:
                data = (directory / f"{variant['coding']}.bin").read_bytes()
                self.assertEqual(len(data), variant["length"])
                self.assertEqual(hashlib.sha256(data).hexdigest(), variant["sha256"])
                if variant["coding"] == 0:
                    self.assertEqual(data, expected)
                elif variant["coding"] == 1:
                    self.assertEqual(gzip.decompress(data), expected)
                    self.assertEqual(data[:10], bytes.fromhex("1f8b08000000000000ff"))
                else:
                    library_directory = Path(subprocess.check_output(
                        ["pkg-config", "--variable=libdir", "libbrotlidec"], text=True).strip())
                    library_path = (library_directory.parent / "bin/libbrotlidec.dll" if sys.platform == "win32" else
                                    library_directory / ("libbrotlidec.dylib" if sys.platform == "darwin" else "libbrotlidec.so"))
                    library = ctypes.CDLL(str(library_path))
                    decoder = library.BrotliDecoderDecompress
                    decoder.argtypes = [ctypes.c_size_t, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p]
                    decoder.restype = ctypes.c_int
                    output = ctypes.create_string_buffer(len(expected)); size = ctypes.c_size_t(len(expected))
                    self.assertEqual(decoder(len(data), ctypes.c_char_p(data), ctypes.byref(size), output), 1)
                    self.assertEqual(output.raw[:size.value], expected)
            self.assertLess(report["packed_size"], 2 * len(expected))


if __name__ == "__main__":
    unittest.main()
