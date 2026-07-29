# Live issues

- Management CIDR has not been provided or safely inferred. Web access remains
  loopback-only.
- Allowed DNS client networks have not been provided. Client DNS access remains
  loopback-only.
- DNS hostname and production certificate data have not been provided.
- `systemd-resolved` is absent; explicit maintenance resolvers are used instead.
- dnsdist encrypted transport capabilities are pending package installation and
  runtime inspection.

