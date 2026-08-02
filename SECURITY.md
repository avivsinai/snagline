# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub Security
Advisories: on the repository's **Security** tab, use **Report a
vulnerability** to open a private advisory. Do not open a public issue or
pull request that describes a suspected vulnerability.

If the private reporting form is not available to you, email the maintainer
directly at avivsinai@gmail.com, or open a minimal public issue stating only
that you have a security report — do not include any technical detail — and
the maintainer will follow up to arrange a private channel.

Include as much of the following as you can:

- the affected command(s), file(s), or protocol family (for example
  `ssp.case.v1`) and, if known, the affected version or commit;
- the class of issue (for example authentication bypass, signature
  verification bypass, TOCTOU, key or credential exposure, memory safety);
- reproduction steps or a proof of concept;
- the impact you believe the issue has.

## Response expectations

Snagline is a pre-1.0 project maintained on a best-effort basis. There is no
guaranteed response time or embargo schedule; reports are triaged and fixed
as maintainer time allows.

## Scope

Snagline's authenticated-artifact and trust-boundary assumptions are
documented in [`docs/ssp/threat-model.md`](docs/ssp/threat-model.md). One
limitation is accepted by design and out of scope: a hostile process running
under the same UID as an edge or projector is not defended against — the
`0700` SQLite state-directory boundary protects against other UIDs, not a
same-UID attacker.
[`docs/operations/pristine-runtime.md`](docs/operations/pristine-runtime.md)
documents dedicated per-role service UIDs as the required mitigation;
enforcing that separation is a deployment responsibility, not something the
runtime itself can guarantee.

Any path where JetStream or Buzz content — an event, membership, ACP result,
channel, cursor, or signature — creates or mutates Snagline semantic state is
exactly the kind of finding to report; that boundary is never expected to be
crossable.
