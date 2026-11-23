import os

# Real installs use 600,000 PBKDF2 rounds; tests use few so they stay fast.
os.environ.setdefault("DNSHOLLOW_PW_ITERATIONS", "1000")
