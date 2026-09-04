# Frontend contract fixtures

The fixture transport derives its operation surface from the checked-in generated Platform
operation registry. It cannot accept a provider URL or a hand-written operation. Tests can
configure response bodies for an operation while the default response remains a generic,
non-disclosing RFC 9457-style failure.

`nonDisclosingDenial()` deliberately returns the same title, shape, and correlation context
without a resource identifier, title, count, route, or policy detail. Request counters make
the one-composed-BFF-call contract measurable without pretending to implement backend SQL,
OpenFGA, provider, or audit behavior.
