# RCXCloud Kill Protocol

- Encrypted (AEAD)
- Device-scoped
- Replay-protected
- One-way irreversible

Kill messages:
- Are validated locally
- Never executed by cloud
- Never expose keys

Fields:
- device_id
- issued_at
- nonce
- scope
