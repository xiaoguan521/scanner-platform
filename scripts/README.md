# Scripts

Add build and verification helpers here as their inputs are pinned. In particular, `make verify-flags` must only pass after it checks the exact locked Nuclei and Trivy binaries; it currently fails closed because the repository has no approved engine version lock.
