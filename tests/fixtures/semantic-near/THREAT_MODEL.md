# Synthetic threat model

## Assets
- Fixture balances and contract state.

## Trusted roles
- Owner is honest for authorized upgrade and pause operations.

## Attacker
- Any unprivileged account can call exported entry points.

## Security properties
- Only the owner may upgrade or pause.
- Balances remain conserved during honest operations.
