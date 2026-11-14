# Runtime Transport

Explicit real runtime GET/SET on the existing owner lease with idempotent SET recovery and mandatory readback.

No implicit runtime flag defaults are selected. An explicit confirmed runtime image
is required before releasing traffic. Errors close the shared lease and withdraw
the complete publication. Runtime SET is idempotent for an exact revision/content
receipt, unlike statistics SWAP. All image updates finish after the final firewall
operation, with runtime before LNA and UID permissions last.

This isolated proposal does not wire Controllers/Binder/Java, collect initial
frames, implement statistics poll persistence or declare networking Ready.
Actual service linking and on-device behavior remain untested.
