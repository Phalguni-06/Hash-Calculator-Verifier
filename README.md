# 🔐 Hash Calculator & Verifier

A lightweight Python command-line utility for cryptographic hashing, file-integrity verification, hash comparison, HMAC, salted hashing, benchmarking, and algorithm/security guidance.

## ✨ Features

- **7 hashing algorithms:** MD5, SHA-1, SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE2b
- Text hashing across all supported algorithms
- File hashing with chunked reads for large files
- Text and file hash verification
- Constant-time hash comparison using `hmac.compare_digest`
- Salted hashing demonstration
- HMAC-SHA256 / HMAC-SHA512 support
- Hash comparison analysis
- Algorithm performance benchmarking
- Security recommendations
- Interactive terminal/Jupyter-friendly interface
- No third-party runtime dependencies

## 📁 Project Structure

```text
hash-calculator-pro/
├── hash_calculator_pro.py
├── tests/
│   └── test_hash_calculator.py
├── .github/
│   └── workflows/
│       └── python-tests.yml
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
└── requirements-dev.txt
```

## 🚀 Quick Start

### Requirements

- Python 3.9+
- Standard library only for the application

### Run

```bash
python hash_calculator_pro.py
```

Then choose an option from the interactive menu.

## 🧰 Menu

1. Hash text (all algorithms)
2. Hash file
3. Verify hash (text)
4. Verify file hash
5. Hash with salt
6. Hash with HMAC
7. Compare two hashes
8. Benchmark algorithms
9. Algorithm information
10. Exit

## 🧪 Testing

Install development dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

Run:

```bash
python -m unittest discover -s tests -v
```

The repository also includes GitHub Actions CI for automated testing.

## 🔒 Security Notes

### Recommended

For general cryptographic hashing, prefer:

- SHA-256
- SHA-512
- SHA3-256
- SHA3-512
- BLAKE2b

### Not recommended for security

MD5 and SHA-1 are retained for compatibility, education, and integrity workflows where appropriate, but should **not** be selected for new security-sensitive designs.

### Password storage

The project's salted-hash feature demonstrates the concept of salting, but a simple fast hash such as SHA-256 is **not the preferred password-storage primitive**. Production password storage should use a dedicated password hashing/KDF such as Argon2id, scrypt, or bcrypt with an appropriate configuration.

Never hard-code real production secrets or passwords into source code.

## 📊 Benchmarking

Benchmark results depend on:

- Python version
- Operating system
- CPU
- input size
- system load

A very short input may produce rounded timing values of `0.00 ms`. The benchmark display protects against division-by-zero in that situation.

## 🧩 Import as a Library

The core functions can be imported:

```python
from hash_calculator_pro import (
    hash_text,
    hash_file,
    verify_hash,
    verify_file,
    hash_with_salt,
    hash_with_hmac,
    compare_hashes,
    benchmark_algorithms,
)

print(hash_text("hello", "sha256"))
```

## 📌 Example

For the text `and`, SHA-256 is:

```text
6201111b83a0cb5b0922cb37cc442b9a40e24e3b1ce100a4bb204f4c63fd2ac0
```

The example mismatch shown in the original interactive session is expected when the supplied expected digest belongs to a different algorithm/value.

## 🛠️ Troubleshooting

### `Error: File path cannot be empty`

Option 2 or 4 requires a non-empty path. Example:

```text
C:\Users\YourName\Documents\example.txt
```

or on Linux/macOS:

```text
/home/user/Documents/example.txt
```

### `ZeroDivisionError` during benchmark

The repository version guards the relative-speed calculation when all measured values round to zero.

## 📜 License

MIT License — see `LICENSE`.

## 👤 Author

**Phalguni Malla**

GitHub: [@Phalguni-06](https://github.com/Phalguni-06)

Repository: [Hash-Calculator-Verifier](https://github.com/Phalguni-06/Hash-Calculator-Verifier)

---

## ⭐ Support

If you find this project useful for learning Python or cybersecurity, consider giving the repository a ⭐ on GitHub.
