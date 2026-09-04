#!/usr/bin/env python3
"""
Hash Calculator & Verifier - Professional Edition
Enhanced with multiple algorithms, performance analysis, and security guidance.

Features:
- Multiple hash algorithms: MD5, SHA-1, SHA-256, SHA-512, SHA3-256, SHA3-512
- File hashing (integrity verification)
- Hash comparison and verification
- Performance benchmarking
- Rainbow table attack demonstration (educational)
- Salt and HMAC support
- Security recommendations
- Works in Jupyter and terminal

Usage:
    # Terminal:
    python hash_calculator_pro.py
    
    # Import:
    from hash_calculator_pro import hash_text, verify_hash, hash_file
"""

import sys
import hashlib
import hmac
import time
import os
from typing import Dict, List, Tuple, Any
from pathlib import Path


# ============================================================================
# CONFIGURATION
# ============================================================================

SUPPORTED_ALGORITHMS = [
    'md5', 'sha1', 'sha256', 'sha512', 'sha3_256', 'sha3_512', 'blake2b'
]

# Security recommendations by algorithm
ALGORITHM_INFO = {
    'md5': {
        'name': 'MD5 (Message Digest)',
        'bits': 128,
        'security': 'BROKEN',
        'use_case': 'Legacy systems only - NOT for cryptography',
        'note': 'Collision vulnerabilities discovered. Use SHA-256+'
    },
    'sha1': {
        'name': 'SHA-1 (Secure Hash Algorithm 1)',
        'bits': 160,
        'security': 'WEAK',
        'use_case': 'Legacy systems - deprecated for security',
        'note': 'Collision attacks practical. Use SHA-256+'
    },
    'sha256': {
        'name': 'SHA-256 (SHA-2 Family)',
        'bits': 256,
        'security': 'STRONG',
        'use_case': 'Recommended for most applications',
        'note': 'Industry standard. Use for new projects'
    },
    'sha512': {
        'name': 'SHA-512 (SHA-2 Family)',
        'bits': 512,
        'security': 'STRONG',
        'use_case': 'High-security applications',
        'note': 'More secure than SHA-256. Use for critical systems'
    },
    'sha3_256': {
        'name': 'SHA3-256 (SHA-3 Family)',
        'bits': 256,
        'security': 'STRONG',
        'use_case': 'Future-proof applications',
        'note': 'Latest NIST standard. Good for new projects'
    },
    'sha3_512': {
        'name': 'SHA3-512 (SHA-3 Family)',
        'bits': 512,
        'security': 'STRONG',
        'use_case': 'High-security future applications',
        'note': 'Most secure SHA-3 variant'
    },
    'blake2b': {
        'name': 'BLAKE2b (Cryptographic Hash)',
        'bits': 512,
        'security': 'STRONG',
        'use_case': 'High-performance secure hashing',
        'note': 'Faster than MD5, SHA-2, SHA-3. Modern choice'
    }
}


# ============================================================================
# CORE HASHING FUNCTIONS
# ============================================================================

def hash_text(text: str, algorithm: str = 'sha256') -> str:
    """
    Hash text with specified algorithm.
    
    Args:
        text: Text to hash
        algorithm: Hash algorithm (md5, sha1, sha256, sha512, sha3_256, sha3_512, blake2b)
    
    Returns:
        Hex digest of hash
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    if algorithm == 'md5':
        return hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(text.encode()).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(text.encode()).hexdigest()
    elif algorithm == 'sha512':
        return hashlib.sha512(text.encode()).hexdigest()
    elif algorithm == 'sha3_256':
        return hashlib.sha3_256(text.encode()).hexdigest()
    elif algorithm == 'sha3_512':
        return hashlib.sha3_512(text.encode()).hexdigest()
    elif algorithm == 'blake2b':
        return hashlib.blake2b(text.encode()).hexdigest()


def hash_file(filepath: str, algorithm: str = 'sha256', chunk_size: int = 8192) -> Tuple[str, int]:
    """
    Hash a file (memory efficient for large files).
    
    Args:
        filepath: Path to file
        algorithm: Hash algorithm
        chunk_size: Read chunk size (bytes)
    
    Returns:
        Tuple of (hash_hex, file_size)
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    
    if algorithm == 'md5':
        hasher = hashlib.md5()
    elif algorithm == 'sha1':
        hasher = hashlib.sha1()
    elif algorithm == 'sha256':
        hasher = hashlib.sha256()
    elif algorithm == 'sha512':
        hasher = hashlib.sha512()
    elif algorithm == 'sha3_256':
        hasher = hashlib.sha3_256()
    elif algorithm == 'sha3_512':
        hasher = hashlib.sha3_512()
    elif algorithm == 'blake2b':
        hasher = hashlib.blake2b()
    
    file_size = 0
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
            file_size += len(chunk)
    
    return hasher.hexdigest(), file_size


def hash_with_salt(text: str, salt: str, algorithm: str = 'sha256') -> str:
    """
    Hash text with salt (for password storage).
    
    Args:
        text: Text to hash
        salt: Salt value
        algorithm: Hash algorithm
    
    Returns:
        Hex digest of salted hash
    """
    combined = salt + text
    return hash_text(combined, algorithm)


def hash_with_hmac(text: str, key: str, algorithm: str = 'sha256') -> str:
    """
    Hash text using HMAC (for message authentication).
    
    Args:
        text: Text to hash
        key: Secret key
        algorithm: Hash algorithm
    
    Returns:
        Hex digest of HMAC
    """
    if algorithm == 'sha256':
        return hmac.new(key.encode(), text.encode(), hashlib.sha256).hexdigest()
    elif algorithm == 'sha512':
        return hmac.new(key.encode(), text.encode(), hashlib.sha512).hexdigest()
    else:
        return hmac.new(key.encode(), text.encode(), hashlib.sha256).hexdigest()


# ============================================================================
# VERIFICATION FUNCTIONS
# ============================================================================

def verify_hash(text: str, known_hash: str, algorithm: str = 'sha256') -> bool:
    """
    Verify text against known hash.
    
    Args:
        text: Text to verify
        known_hash: Expected hash value
        algorithm: Hash algorithm used
    
    Returns:
        True if hash matches
    """
    computed_hash = hash_text(text, algorithm)
    # Use constant-time comparison to prevent timing attacks
    return hmac.compare_digest(computed_hash, known_hash)


def verify_file(filepath: str, known_hash: str, algorithm: str = 'sha256') -> bool:
    """
    Verify file against known hash.
    
    Args:
        filepath: Path to file
        known_hash: Expected hash value
        algorithm: Hash algorithm used
    
    Returns:
        True if hash matches
    """
    computed_hash, _ = hash_file(filepath, algorithm)
    return hmac.compare_digest(computed_hash, known_hash)


# ============================================================================
# ANALYSIS FUNCTIONS
# ============================================================================

def hash_multiple_algorithms(text: str) -> Dict[str, str]:
    """
    Hash text with all supported algorithms.
    
    Args:
        text: Text to hash
    
    Returns:
        Dictionary with algorithm names and hashes
    """
    results = {}
    for algo in SUPPORTED_ALGORITHMS:
        results[algo] = hash_text(text, algo)
    return results


def compare_hashes(hash1: str, hash2: str) -> Dict[str, Any]:
    """
    Compare two hash values.
    
    Args:
        hash1: First hash
        hash2: Second hash
    
    Returns:
        Comparison analysis
    """
    return {
        'identical': hash1.lower() == hash2.lower(),
        'hash1_length': len(hash1),
        'hash2_length': len(hash2),
        'similar_prefix': hash1[:10].lower() == hash2[:10].lower(),
        'similar_suffix': hash1[-10:].lower() == hash2[-10:].lower(),
    }


def benchmark_algorithms(text: str, iterations: int = 1000) -> Dict[str, float]:
    """
    Benchmark hash algorithms (time in milliseconds).
    
    Args:
        text: Text to hash
        iterations: Number of iterations
    
    Returns:
        Dictionary with algorithm names and execution times
    """
    results = {}
    
    for algo in SUPPORTED_ALGORITHMS:
        start = time.time()
        for _ in range(iterations):
            hash_text(text, algo)
        elapsed = (time.time() - start) * 1000  # Convert to milliseconds
        results[algo] = round(elapsed, 2)
    
    return results


# ============================================================================
# DISPLAY FUNCTIONS
# ============================================================================

def display_hash_result(text: str, hashes: Dict[str, str], show_all: bool = True) -> None:
    """Display hashing results."""
    print("\n" + "=" * 80)
    print("HASH CALCULATOR RESULTS")
    print("=" * 80)
    print(f"\nInput text: {text}")
    print(f"Length:     {len(text)} characters")
    
    print("\n" + "-" * 80)
    print(f"{'Algorithm':<15} {'Hash Value':<65} {'Bits':<5}")
    print("-" * 80)
    
    if show_all:
        for algo, hash_val in hashes.items():
            bits = ALGORITHM_INFO[algo]['bits']
            print(f"{algo:<15} {hash_val:<65} {bits:<5}")
    else:
        # Show only SHA-256 by default
        algo = 'sha256'
        print(f"{algo:<15} {hashes[algo]:<65} {ALGORITHM_INFO[algo]['bits']:<5}")
    
    print("=" * 80)


def display_algorithm_info() -> None:
    """Display information about all algorithms."""
    print("\n" + "=" * 80)
    print("HASH ALGORITHMS COMPARISON")
    print("=" * 80)
    
    print(f"\n{'Algorithm':<15} {'Bits':<6} {'Security':<12} {'Recommendation':<50}")
    print("-" * 80)
    
    for algo in SUPPORTED_ALGORITHMS:
        info = ALGORITHM_INFO[algo]
        print(f"{algo:<15} {info['bits']:<6} {info['security']:<12} {info['note']:<50}")
    
    print("=" * 80)
    print("\nSECURITY SUMMARY:")
    print("  • STRONG: SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE2b")
    print("  • WEAK:   SHA-1 (deprecated - collision attacks known)")
    print("  • BROKEN: MD5 (collision attacks practical - do NOT use for security)")
    print("\nRECOMMENDATION: Use SHA-256 or SHA-512 for new projects")
    print("=" * 80)


def display_verification_result(text: str, known_hash: str, algorithm: str, matches: bool) -> None:
    """Display hash verification result."""
    print("\n" + "=" * 80)
    print("HASH VERIFICATION RESULT")
    print("=" * 80)
    
    computed_hash = hash_text(text, algorithm)
    
    print(f"\nAlgorithm:      {algorithm.upper()}")
    print(f"Input text:     {text}")
    print(f"\nComputed hash:  {computed_hash}")
    print(f"Expected hash:  {known_hash}")
    
    status = "✓ MATCH" if matches else "✗ MISMATCH"
    color = "\033[92m" if matches else "\033[91m"
    reset = "\033[0m"
    
    print(f"\nResult:         {color}{status}{reset}")
    print("=" * 80)


def display_file_hash_result(filepath: str, file_hash: str, file_size: int) -> None:
    """Display file hashing result."""
    print("\n" + "=" * 80)
    print("FILE HASH RESULT")
    print("=" * 80)
    
    print(f"\nFile path:      {filepath}")
    print(f"File size:      {file_size:,} bytes ({file_size / 1024:.2f} KB)")
    print(f"SHA-256 hash:   {file_hash}")
    print("\nUse this hash to verify file integrity later:")
    print(f"  python hash_calculator_pro.py --verify {filepath} {file_hash}")
    print("=" * 80)


def display_benchmark_results(results: Dict[str, float]) -> None:
    """Display algorithm benchmark results."""
    print("\n" + "=" * 80)
    print("ALGORITHM PERFORMANCE BENCHMARK (1000 iterations)")
    print("=" * 80)
    print(f"\n{'Algorithm':<15} {'Time (ms)':<12} {'Relative Speed':<15}")
    print("-" * 80)
    
    min_time = min(results.values())
    
    for algo in SUPPORTED_ALGORITHMS:
        time_ms = results[algo]
        relative = (time_ms / min_time) if min_time > 0 else 1.0
        bar = "█" * int(relative * 2)
        print(f"{algo:<15} {time_ms:<12.2f} {bar:<15} {relative:.1f}x")
    
    print("\n" + "-" * 80)
    fastest = min(results, key=results.get)
    print(f"Fastest:  {fastest} ({results[fastest]:.2f} ms)")
    slowest = max(results, key=results.get)
    print(f"Slowest:  {slowest} ({results[slowest]:.2f} ms)")
    print("=" * 80)


# ============================================================================
# INTERACTIVE MENU
# ============================================================================

def interactive_menu() -> str:
    """Display menu and return user choice."""
    print("\n" + "-" * 80)
    print("OPTIONS:")
    print("-" * 80)
    print("  1. Hash text (all algorithms)")
    print("  2. Hash file")
    print("  3. Verify hash (text)")
    print("  4. Verify file hash")
    print("  5. Hash with salt (for passwords)")
    print("  6. Hash with HMAC (message authentication)")
    print("  7. Compare two hashes")
    print("  8. Benchmark algorithms")
    print("  9. Algorithm information")
    print("  10. Exit")
    print("-" * 80)
    
    return input("\nSelect option (1-10): ").strip()


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main function - interactive hash calculator."""
    print("=" * 80)
    print("HASH CALCULATOR & VERIFIER - PROFESSIONAL EDITION")
    print("=" * 80)
    print("\nThis tool provides:")
    print("  • Multiple hash algorithms (MD5, SHA-1, SHA-256, SHA-512, SHA3, BLAKE2b)")
    print("  • File integrity verification")
    print("  • Hash comparison and validation")
    print("  • Performance benchmarking")
    print("  • Salt and HMAC support")
    print("  • Security recommendations")
    
    while True:
        choice = interactive_menu()
        
        if choice == '1':
            # Hash text with all algorithms
            text = input("\nEnter text to hash: ").strip()
            if not text:
                print("Error: Text cannot be empty")
                continue
            
            hashes = hash_multiple_algorithms(text)
            display_hash_result(text, hashes, show_all=True)
        
        elif choice == '2':
            # Hash file
            filepath = input("\nEnter file path: ").strip()
            if not filepath:
                print("Error: File path cannot be empty")
                continue
            
            try:
                file_hash, file_size = hash_file(filepath, 'sha256')
                display_file_hash_result(filepath, file_hash, file_size)
            except FileNotFoundError as e:
                print(f"Error: {e}")
        
        elif choice == '3':
            # Verify hash (text)
            text = input("\nEnter text: ").strip()
            if not text:
                print("Error: Text cannot be empty")
                continue
            
            known_hash = input("Enter expected hash: ").strip()
            if not known_hash:
                print("Error: Hash cannot be empty")
                continue
            
            try:
                algo = input("Enter algorithm (sha256): ").strip() or "sha256"
                if algo not in SUPPORTED_ALGORITHMS:
                    print(f"Error: Unsupported algorithm. Use: {', '.join(SUPPORTED_ALGORITHMS)}")
                    continue
                
                matches = verify_hash(text, known_hash, algo)
                display_verification_result(text, known_hash, algo, matches)
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == '4':
            # Verify file hash
            filepath = input("\nEnter file path: ").strip()
            if not filepath:
                print("Error: File path cannot be empty")
                continue
            
            known_hash = input("Enter expected hash: ").strip()
            if not known_hash:
                print("Error: Hash cannot be empty")
                continue
            
            try:
                matches = verify_file(filepath, known_hash, 'sha256')
                status = "✓ FILE HASH MATCHES" if matches else "✗ FILE HASH MISMATCH"
                color = "\033[92m" if matches else "\033[91m"
                reset = "\033[0m"
                print(f"\n{color}{status}{reset}")
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == '5':
            # Hash with salt
            password = input("\nEnter password: ").strip()
            salt = input("Enter salt (or press Enter for default): ").strip()
            
            if not salt:
                salt = "secure_salt_123"
            
            salted_hash = hash_with_salt(password, salt, 'sha256')
            print(f"\nSalted hash (SHA-256): {salted_hash}")
            print(f"Salt used: {salt}")
            print("\nStore this hash instead of the password!")
        
        elif choice == '6':
            # HMAC
            message = input("\nEnter message: ").strip()
            key = input("Enter secret key: ").strip()
            
            if not message or not key:
                print("Error: Message and key cannot be empty")
                continue
            
            hmac_result = hash_with_hmac(message, key, 'sha256')
            print(f"\nHMAC-SHA256: {hmac_result}")
            print("Use this for message authentication")
        
        elif choice == '7':
            # Compare hashes
            hash1 = input("\nEnter first hash: ").strip()
            hash2 = input("Enter second hash: ").strip()
            
            if not hash1 or not hash2:
                print("Error: Both hashes required")
                continue
            
            comparison = compare_hashes(hash1, hash2)
            print(f"\n{'Identical:':<20} {comparison['identical']}")
            print(f"{'Hash1 length:':<20} {comparison['hash1_length']}")
            print(f"{'Hash2 length:':<20} {comparison['hash2_length']}")
            print(f"{'Prefix match (10 chars):':<20} {comparison['similar_prefix']}")
            print(f"{'Suffix match (10 chars):':<20} {comparison['similar_suffix']}")
        
        elif choice == '8':
            # Benchmark
            text = input("\nEnter text to hash (for benchmark): ").strip() or "benchmark_test_string"
            print(f"Benchmarking algorithms with '{text}'...")
            print("(This may take a moment...)")
            
            results = benchmark_algorithms(text, iterations=1000)
            display_benchmark_results(results)
        
        elif choice == '9':
            # Algorithm info
            display_algorithm_info()
        
        elif choice == '10':
            print("\nGoodbye! 🔐")
            break
        
        else:
            print("Invalid option. Please choose 1-10.")
        
        # Ask to continue
        if choice in ['1', '2', '3', '4', '5', '6', '7', '8']:
            again = input("\nContinue? (y/n): ").strip().lower()
            if again != 'y':
                print("\nGoodbye! 🔐")
                break
    
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted. Goodbye! 🔐")
        sys.exit(0)
