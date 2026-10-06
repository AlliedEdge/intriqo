"""Typed flow-feature contract consumption; no model execution."""

from .flow_features import (
    MAX_RECORD_BYTES,
    FlowFeatureError,
    FlowFeatureRecord,
    FlowFeatures,
    FlowMetadata,
    FlowNetwork,
    NanosecondTimestamp,
    UnsupportedSchemaVersionError,
    flow_feature_json_schema,
    parse_flow_feature_record,
)
from .flow_features_v2 import (
    FlowFeatureLineV2,
    FlowFeatureRecordV2,
    flow_feature_json_schema_v2,
    iter_flow_feature_records_v2,
    parse_flow_feature_record_v2,
)

__all__ = [
    "MAX_RECORD_BYTES",
    "FlowFeatureError",
    "FlowFeatureLineV2",
    "FlowFeatureRecord",
    "FlowFeatureRecordV2",
    "FlowFeatures",
    "FlowMetadata",
    "FlowNetwork",
    "NanosecondTimestamp",
    "UnsupportedSchemaVersionError",
    "flow_feature_json_schema",
    "flow_feature_json_schema_v2",
    "iter_flow_feature_records_v2",
    "parse_flow_feature_record",
    "parse_flow_feature_record_v2",
]
