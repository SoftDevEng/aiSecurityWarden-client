"""Regenerate tests/vectors/crypto-v1.json after any change to crypto.py (run from the repo root).
Same as: python -m securitywarden.vectors"""

from securitywarden.vectors import main

if __name__ == "__main__":
    main()
