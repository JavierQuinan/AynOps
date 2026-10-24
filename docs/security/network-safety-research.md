# Network Safety Guard — research status

Scope: isolated research in JavierQuinan/AynOps, branch security/network-safety-research.
No changes to upstream, fork main, or the public MCP tool contract.

## Observed baseline
- tools/techstack_tool.py uses requests.get(..., allow_redirects=True).
- utils/helpers.py checks domain syntax, not the destination address.
- Existing research tests characterize this behavior and mark desired
  destination rejection as strict expected failures.
- These observations are NOT a demonstrated SSRF exploit.

## Prototype
- utils/network_safety.py contains pure fail-closed address classification.
- tests/test_network_safety_policy.py covers IPv4/IPv6, mixed DNS answers,
  empty answers, deduplication, and invalid addresses.
- The prototype is not integrated into the HTTP transport. It must not be
  described as a complete SSRF mitigation.

## Security invariants required before integration
1. Validate all resolved addresses, not only the first result.
2. Bind the actual connection to an approved address; preserve the original
   hostname for TLS SNI, certificate validation and HTTP Host semantics.
3. Disable automatic redirect following. Parse and validate every redirect
   target before the next connection, including schemes, ports and userinfo.
4. Enforce bounded redirects, response sizes, connection/read timeouts,
   and a deliberate proxy policy.
5. Permit internal-network scanning only through an explicit, reviewed
   configuration, not as a silent fallback.
6. Test IPv4, IPv6, DNS changes, redirects, proxies and compatibility.
7. Keep errors structured and avoid disclosing credentials in logs.

## Validation limitations
GitHub remote operations work through the connected GitHub tool, but the
local runtime could not resolve github.com to clone the repository. No
pytest run, CI success, or exploit reproduction is claimed here.

## Next gate
Run the complete suite in a checkout, then build a connection-pinned HTTP
transport with deterministic tests before changing the MCP entry point.
