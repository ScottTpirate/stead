# modules/audit

WS-07 owns protected audit evidence and canonical event serialization.

`CreatedEvent` encodes the Organization, Team and Project creation events used
by the real core PostgreSQL transaction/outbox path.

`EffectEvent` and `DecodeEffectEvent` encode and validate the bounded synchronous
User provider-effect lifecycle envelope. Its authorization producer and event
type route to `stead.authorization.changed.v1`, even though its canonical
resource is a Project. The envelope carries only transition identity and safe
routing/label/actor metadata, not provider inputs, credentials or terminal proof.
The current native slice admits sensitivity-only labels; unsupported dimensions
fail closed, rather than being dropped. Decoder output is never authorization,
dispatch authority, proof of a terminal effect, or a revocation-drain receipt.

The effect codec is an integration component, not evidence of NATS delivery.
The PostgreSQL lifecycle producer, registered delivery consumer and durable
consumer outcome must be demonstrated before claiming end-to-end effect-event
delivery. Background recovery cannot borrow a historical User as its actor.
