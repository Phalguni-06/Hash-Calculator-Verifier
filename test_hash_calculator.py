import sys
import hashlib
from pathlib import Path

# Allow tests to import the repository's single-file application module.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import tempfile
import unittest
from pathlib import Path

from hash_calculator_pro import (
    SUPPORTED_ALGORITHMS,
    benchmark_algorithms,
    compare_hashes,
    hash_file,
    hash_multiple_algorithms,
    hash_text,
    hash_with_hmac,
    hash_with_salt,
    verify_file,
    verify_hash,
)


class TestHashCalculator(unittest.TestCase):

    def test_all_algorithms_are_available(self):
        results = hash_multiple_algorithms("and")
        self.assertEqual(set(results), set(SUPPORTED_ALGORITHMS))
        self.assertEqual(len(results["md5"]), 32)
        self.assertEqual(len(results["sha1"]), 40)
        self.assertEqual(len(results["sha256"]), 64)
        self.assertEqual(len(results["sha512"]), 128)
        self.assertEqual(len(results["sha3_256"]), 64)
        self.assertEqual(len(results["sha3_512"]), 128)
        self.assertEqual(len(results["blake2b"]), 128)

    def test_sha256_known_value(self):
        expected = hashlib.sha256(b"and").hexdigest()
        self.assertEqual(hash_text("and", "sha256"), expected)

    def test_verify_hash(self):
        digest = hash_text("hello", "sha256")
        self.assertTrue(verify_hash("hello", digest, "sha256"))
        self.assertFalse(verify_hash("hello!", digest, "sha256"))

    def test_file_hash_and_verify(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sample.txt"
            path.write_text("hello file", encoding="utf-8")
            digest, size = hash_file(str(path), "sha256")
            self.assertEqual(size, len("hello file".encode("utf-8")))
            self.assertTrue(verify_file(str(path), digest, "sha256"))

    def test_salt_changes_result(self):
        plain = hash_text("password", "sha256")
        salted = hash_with_salt("password", "abcd", "sha256")
        self.assertNotEqual(plain, salted)

    def test_hmac(self):
        result = hash_with_hmac("message", "secret", "sha256")
        expected = __import__("hmac").new(
            b"secret", b"message", hashlib.sha256
        ).hexdigest()
        self.assertEqual(result, expected)

    def test_compare_hashes(self):
        self.assertTrue(compare_hashes("ABCDEF", "abcdef")["identical"])
        self.assertFalse(compare_hashes("abc", "abcd")["identical"])

    def test_benchmark_never_divides_by_zero(self):
        results = benchmark_algorithms("x", iterations=1)
        self.assertEqual(set(results), set(SUPPORTED_ALGORITHMS))
        self.assertTrue(all(value >= 0 for value in results.values()))


if __name__ == "__main__":
    unittest.main()
