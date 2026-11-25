---
trigger: always_on
description: Require tests and remote verification on the newos-dev VM for every code change.
---

# Mandatory Test & `newos-dev` Verification Rule

Every time you **add, modify, or delete** any line of code in this repository, you MUST:

1. **Create or update tests** covering the added, modified, or removed behavior (unit tests and/or E2E tests as appropriate).
2. **Run local checks**:
   - `cargo fmt --check`
   - `cargo clippy --all-targets -- -D warnings`
   - `cargo test`
3. **Sync your changes to the `newos-dev` GCP VM** (`/home/laurentgrangeau/newos`) via IAP (`--project=lgu-demos --zone=europe-west1-b --tunnel-through-iap`).
4. **Run the full AArch64 build and QEMU boot self-test suite on `newos-dev`**:
   ```bash
   gcloud compute ssh newos-dev \
     --project=lgu-demos \
     --zone=europe-west1-b \
     --tunnel-through-iap \
     --command="source /etc/profile.d/rust.sh && cd ~/newos && cargo xtask test"
   ```
5. Confirm all host tests, AArch64 bare-metal builds, and QEMU guest self-tests (`PSCI SYSTEM_OFF (status=OK)`) pass before reporting the task complete.
