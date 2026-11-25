## Summary

Describe the problem and intended behavior.

## Changes

- 

## Verification

- [ ] cargo fmt --all -- --check
- [ ] cargo check --workspace --all-targets
- [ ] cargo test --workspace
- [ ] cargo clippy --workspace --all-targets -- -D warnings
- [ ] Updated documentation and configuration examples where needed.
- [ ] Tested IPv4 and IPv6 separately where networking behavior changed.
- [ ] Tested teardown/rollback and failure paths for privileged networking changes.

Commands run and results:

## Networking and security impact

- Does this change affect routing, forwarding, NAT, DNS, kill-switch policy, packet parsing, authentication, crypto, or secret handling?
- Does it change the trust boundary or require new privileges?
- Are any migration or configuration changes required?

## Checklist

- [ ] I reviewed the Code of Conduct and contributing guide.
- [ ] I did not include secrets, credentials, or private user data.
- [ ] Third-party code retains required attribution and license notices.
- [ ] The PR describes unverified behavior and known limitations.
