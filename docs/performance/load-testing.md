# Load Testing Methodology

## Test Harness
- Load tests evaluate system resilience under synthetic packet floods and high flow volumes.
- Scenarios located in `tests/performance/`.

## Test Execution
- Run engine replay under simulated 10k concurrent flows:
  `./scripts/benchmark/benchmark.sh`
- Measure dropped packet ratio, memory consumption ceiling, and flow expiration handling under stress.
