# Intriqo Datasets

This directory holds network traffic datasets, benchmark traces, and feature matrices used for ML models and detection rule evaluation.

## Organization
- `raw/`: Unprocessed traffic flow logs, raw telemetry, and benchmark captures.
- `processed/`: Normalized feature sets, CSV/Parquet files ready for ML training.

*Note: Large binary dataset files (>50MB) should be tracked via Git LFS or stored externally in S3/cloud storage.*
