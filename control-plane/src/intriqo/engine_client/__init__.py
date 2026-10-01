"""Engine client — the only boundary through which Python communicates with the C++ IDS engine.

Architecture rule: NO Python code outside this package may call the engine directly.
The engine client translates SecurityEvent JSON (produced by the engine) into the
cross-boundary contract defined in contracts/events/ and forwards it to the agent
platform and persistence layer.
"""
