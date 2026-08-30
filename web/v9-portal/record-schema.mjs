const MAX_DEPTH = 16;
const MAX_CONTAINER_ITEMS = 2_000;
const MAX_STRING_LENGTH = 200_000;

const RECORD_SCHEMAS_V1 = Object.freeze({
  source: { required: [], strings: ["title", "name", "url"] },
  evidence: { required: [], strings: ["title", "summary", "source"] },
  claim: { required: [], strings: ["statement", "title", "status"] },
  entity: { required: [], strings: ["name", "entity_type"] },
  relation: { required: [], strings: ["subject_id", "object_id", "relation_type"] },
  geo_event: { required: [], strings: ["title", "occurred_at"] },
  alert_rule: { required: [], strings: ["name", "severity"] },
  alert: { required: [], strings: ["title", "status", "state"] },
  case: { required: [], strings: ["title", "status", "state"] },
  job: { required: [], strings: ["title", "status", "state"] },
  scenario: { required: [], strings: ["title", "status", "state"] },
  document: { required: [], strings: ["title", "kind", "stage"] },
  publication_item: {
    required: [],
    strings: ["title", "status", "document_id"],
  },
  audit_event: { required: [], strings: ["action", "target_id"] },
});


export class RecordPlaintextError extends Error {
  constructor(code) {
    super(code);
    this.name = "RecordPlaintextError";
    this.code = code;
  }
}


function isPlainObject(value) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}


function validateJsonShape(value, depth = 0) {
  if (depth > MAX_DEPTH) throw new RecordPlaintextError("invalid_schema");
  if (typeof value === "string") {
    if (value.length > MAX_STRING_LENGTH) {
      throw new RecordPlaintextError("invalid_schema");
    }
    return;
  }
  if (
    value === null
    || typeof value === "boolean"
    || (typeof value === "number" && Number.isFinite(value))
  ) {
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > MAX_CONTAINER_ITEMS) {
      throw new RecordPlaintextError("invalid_schema");
    }
    for (const item of value) validateJsonShape(item, depth + 1);
    return;
  }
  if (!isPlainObject(value)) throw new RecordPlaintextError("invalid_schema");
  const entries = Object.entries(value);
  if (entries.length > MAX_CONTAINER_ITEMS) {
    throw new RecordPlaintextError("invalid_schema");
  }
  for (const [key, item] of entries) {
    if (!key || key.length > 200) throw new RecordPlaintextError("invalid_schema");
    validateJsonShape(item, depth + 1);
  }
}


export function validateRecordPlaintext(recordType, value) {
  const schema = RECORD_SCHEMAS_V1[String(recordType || "")];
  if (!schema) throw new RecordPlaintextError("invalid_schema");
  if (!isPlainObject(value)) throw new RecordPlaintextError("invalid_schema");
  const schemaVersion = value.schema_version ?? 1;
  if (!Number.isInteger(schemaVersion) || schemaVersion !== 1) {
    throw new RecordPlaintextError("unsupported_schema");
  }
  validateJsonShape(value);
  for (const field of schema.required) {
    if (typeof value[field] !== "string" || !value[field].trim()) {
      throw new RecordPlaintextError("invalid_schema");
    }
  }
  for (const field of schema.strings) {
    if (value[field] !== undefined && typeof value[field] !== "string") {
      throw new RecordPlaintextError("invalid_schema");
    }
  }
  return value;
}
