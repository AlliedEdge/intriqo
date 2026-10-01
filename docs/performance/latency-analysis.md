# Latency Analysis

Intriqo categorizes latency requirements across three critical paths:

1. **Detection Critical Path (C++ Engine)**:
   - Wire-to-detection latency budget: **< 1 millisecond**.
   - Requires zero allocation on hot loop packet parsing.

2. **Ingestion & Alert Path (Engine -> Control Plane)**:
   - Event delivery to control plane: **< 50 milliseconds**.

3. **Autonomous Investigation Path (Agents)**:
   - Tool querying, LLM reasoning, correlation: **1 to 5 seconds**.
   - Async decoupled processing so detection latency remains unaffected.
