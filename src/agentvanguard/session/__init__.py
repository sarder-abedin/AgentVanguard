"""Session state storage.

`Engine.authorize()` tracks per-session runtime counters (step count,
tool-call count, recent tool-call hashes for repetition detection) in a
`SessionState`, persisted between calls through a `SessionStore`. This
subpackage defines that storage contract (`store.py`) and two
implementations: `InMemorySessionStore` (process-local, the default) and
`RedisSessionStore` (`redis_store.py`, shared across replicas). `factory.py`
selects between them based on `config.session_store.backend`.
"""
