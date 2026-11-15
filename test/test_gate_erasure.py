#!/usr/bin/env python3
"""Check the generated Lean C representation of a gate admission.

`Admitted` has eight runtime fields and three Prop proof fields. The proofs
must not appear in the constructor emitted by the pinned Lean toolchain.
This is a representation check, not a claim that admission allocates nothing.
"""

from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
POLICY_C = ROOT / ".lake/build/ir/LeanNet/Gate/Policy.c"
ADMIT_HEAD = "lp_lean_x2dnet_LeanNet_Gate_admitHead"


def function_body(source, name):
    match = re.search(
        rf"LEAN_EXPORT lean_object\* {re.escape(name)}\(lean_object\* v_policy_[^\n]*\)\{{",
        source,
    )
    if match is None:
        raise AssertionError(f"generated C is missing {name}")
    start = match.end()
    depth = 1
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index]
    raise AssertionError(f"unterminated generated C function {name}")


class GateProofErasure(unittest.TestCase):
    def test_admission_theorems_have_no_sorry(self):
        source = (
            "import LeanNet.Gate.Policy\n"
            "#print axioms LeanNet.Gate.fieldOk_no_crlf\n"
            "#print axioms LeanNet.Gate.Admitted.backend_serves\n"
        )
        with tempfile.TemporaryDirectory(prefix="lean-net-gate-axioms-") as directory:
            lean_file = Path(directory) / "Axioms.lean"
            lean_file.write_text(source)
            environment = os.environ.copy()
            environment["LEAN_PATH"] = os.pathsep.join(
                filter(None, (str(ROOT / ".lake/build/lib/lean"), environment.get("LEAN_PATH")))
            )
            result = subprocess.run(
                ["lean", str(lean_file)], cwd=ROOT, env=environment,
                capture_output=True, text=True, timeout=30,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("'LeanNet.Gate.fieldOk_no_crlf'", result.stdout)
        self.assertIn("'LeanNet.Gate.Admitted.backend_serves'", result.stdout)
        self.assertNotIn("sorryAx", result.stdout)

    def test_admitted_proofs_are_erased(self):
        self.assertTrue(POLICY_C.is_file(), "build LeanNet.Gate.Policy first")
        body = function_body(POLICY_C.read_text(), ADMIT_HEAD)
        allocations = re.findall(
            r"(v_[A-Za-z0-9_]+) = lean_alloc_ctor\(0, 8, 0\);", body
        )
        self.assertTrue(allocations, "no eight-field Admitted constructor found")
        for variable in allocations:
            indices = re.findall(
                rf"lean_ctor_set\({re.escape(variable)}, (\d+),", body
            )
            self.assertEqual(indices, [str(index) for index in range(8)])


if __name__ == "__main__":
    unittest.main()
