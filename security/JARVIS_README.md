# JARVIS | Public research integrity watcher (proposed)

**Status: DRAFT PULL REQUEST. Human-led research. No autonomous protection deployment.**

## What it does
- Freezes 11 already-published public-safe reference files from Nov 19–21, 2026 using exact Git blob IDs, based on the Nov 22 GitHub snapshot.
- Computes a fresh SHA3-512 fingerprint when it runs and compares source files with the frozen Git baseline.
- Detects missing/modified historical files and a narrow set of credential markers.
- Uses no-network, read-only Python and three offline tests.
- Runs on relevant PRs and changes; schedules one daily low-cost check only if merged into main.
- Uses SHA-pinned checkout, read-only GITHUB_TOKEN, no secrets, no auto-write, no outbound notifications.

## What it cannot claim
- SHA3-512 hashing is not digital signing. This workflow does not implement NIST FIPS 204 ML-DSA or FIPS 205 SLH-DSA.
- Git blob IDs are SHA-1 legacy identifiers, not quantum-safe authentication.
- Someone who can change the checker and baseline together can evade a self-check. Use independent reviews and protected main.
- Credential scanning here is intentionally narrow, not comprehensive secret scanning, military defense or an ASI.
- No confidential manuscripts, testimony, correspondence or personal data are scanned.

## Planned post-quantum migration
1. Inventory signing, encryption and access requirements.
2. Trial reviewed FIPS 204/205 digital-signature implementations with keys stored outside GitHub.
3. Verify against independently trusted public keys; no private keys in the repository.
4. Evaluate FIPS 203 ML-KEM only where key establishment is needed.
5. Require external witness verification before claiming authenticity guarantees.

NIST standards: https://csrc.nist.gov/Projects/Post-Quantum-Cryptography

## Boundaries | Límites
**No hacking, autonomous retaliation, military engagement or bulk outreach. No personal profiling.**
**Sin ataques, represalias cibernéticas, acciones militares ni publicación de archivos privados.**

For real incidents, use authorized response channels and preserve evidence. Human approval for each release.

## Verification
Run: python3 -m unittest discover -s tests -p test_jarvis_integrity.py
Then: python3 scripts/jarvis_integrity.py --root . --manifest security/jarvis_baseline.json

This guards baseline consistency, not the truth of scientific claims. Document and review any intentional source changes.
