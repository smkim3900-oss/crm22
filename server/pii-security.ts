import crypto from "crypto";

const PII_ENVELOPE_KIND = "crm.pii.envelope";
const PII_ENVELOPE_VERSION_V1 = 1;
const PII_ENVELOPE_VERSION_V2 = 2;
const PII_ENVELOPE_ALGORITHM = "aes-256-gcm";

interface PiiEnvelopeV1 {
  kind: typeof PII_ENVELOPE_KIND;
  version: typeof PII_ENVELOPE_VERSION_V1;
  algorithm: typeof PII_ENVELOPE_ALGORITHM;
  salt: string;
  iv: string;
  tag: string;
  ciphertext: string;
}

interface PiiEnvelopeV2 {
  kind: typeof PII_ENVELOPE_KIND;
  version: typeof PII_ENVELOPE_VERSION_V2;
  algorithm: typeof PII_ENVELOPE_ALGORITHM;
  iv: string;
  tag: string;
  ciphertext: string;
}

export const STORAGE_PII_FIELDS = {
  users: ["email", "phone"] as const,
  customers: ["email", "phone", "notes"] as const,
  contacts: ["name", "email", "phone"] as const,
  deals: ["phone", "email", "billingAccountNumber", "notes"] as const,
  payments: ["notes"] as const,
  systemLogs: ["loginId", "userName", "ipAddress", "userAgent", "details"] as const,
  contracts: ["userIdentifier", "notes"] as const,
  refunds: ["userIdentifier", "account"] as const,
  keeps: ["userIdentifier"] as const,
  deposits: ["depositorName", "notes"] as const,
  quotations: [
    "customerPhone",
    "customerEmail",
    "customerName",
    "customerCompany",
    "projectName",
    "notes",
    "createdByEmail",
    "createdByPhone",
  ] as const,
} as const;

export const RAW_TABLE_PII_COLUMNS = {
  users: ["email", "phone"] as const,
  customers: ["email", "phone", "notes"] as const,
  contacts: ["name", "email", "phone"] as const,
  deals: ["phone", "email", "billing_account_number", "notes"] as const,
  payments: ["notes"] as const,
  system_logs: ["login_id", "user_name", "ip_address", "user_agent", "details"] as const,
  contracts: ["user_identifier", "notes"] as const,
  refunds: ["user_identifier", "account"] as const,
  keeps: ["user_identifier"] as const,
  deposits: ["depositor_name", "notes"] as const,
  quotations: [
    "customer_phone",
    "customer_email",
    "customer_name",
    "customer_company",
    "project_name",
    "notes",
    "created_by_email",
    "created_by_phone",
  ] as const,
  customer_counselings: ["content"] as const,
  customer_change_histories: ["before_data", "after_data"] as const,
  customer_files: ["file_name", "original_file_name", "file_data", "note"] as const,
} as const;

function getPiiEncryptionSecret(): string | null {
  const value = String(process.env.PII_ENCRYPTION_KEY || "").trim();
  return value || null;
}

function deriveEncryptionKey(secret: string, salt: Buffer) {
  return crypto.scryptSync(secret, salt, 32);
}

let cachedSecretForStaticKey: string | null = null;
let cachedStaticKey: Buffer | null = null;

function getStaticEncryptionKey(secret: string) {
  if (cachedStaticKey && cachedSecretForStaticKey === secret) {
    return cachedStaticKey;
  }
  cachedSecretForStaticKey = secret;
  cachedStaticKey = crypto.createHash("sha256").update(secret, "utf8").digest();
  return cachedStaticKey;
}

function requireBufferFromBase64(value: string, label: string): Buffer {
  try {
    return Buffer.from(value, "base64");
  } catch {
    throw new Error(`Invalid encrypted PII ${label}.`);
  }
}

function isPiiEnvelopeV1(value: unknown): value is PiiEnvelopeV1 {
  if (!value || typeof value !== "object") return false;
  const envelope = value as Record<string, unknown>;
  return (
    envelope.kind === PII_ENVELOPE_KIND &&
    envelope.version === PII_ENVELOPE_VERSION_V1 &&
    envelope.algorithm === PII_ENVELOPE_ALGORITHM &&
    typeof envelope.salt === "string" &&
    typeof envelope.iv === "string" &&
    typeof envelope.tag === "string" &&
    typeof envelope.ciphertext === "string"
  );
}

function isPiiEnvelopeV2(value: unknown): value is PiiEnvelopeV2 {
  if (!value || typeof value !== "object") return false;
  const envelope = value as Record<string, unknown>;
  return (
    envelope.kind === PII_ENVELOPE_KIND &&
    envelope.version === PII_ENVELOPE_VERSION_V2 &&
    envelope.algorithm === PII_ENVELOPE_ALGORITHM &&
    typeof envelope.iv === "string" &&
    typeof envelope.tag === "string" &&
    typeof envelope.ciphertext === "string"
  );
}

function isPiiEnvelope(value: unknown): value is PiiEnvelopeV1 | PiiEnvelopeV2 {
  return isPiiEnvelopeV1(value) || isPiiEnvelopeV2(value);
}

export function isPiiEncryptionConfigured() {
  return Boolean(getPiiEncryptionSecret());
}

export function assertPiiEncryptionReadyForProduction() {
  if (process.env.NODE_ENV === "production" && !isPiiEncryptionConfigured()) {
    console.warn("PII_ENCRYPTION_KEY is not set; encrypted PII operations will be unavailable.");
  }
}

export function isEncryptedPiiStoredValue(value: unknown): boolean {
  if (typeof value !== "string") return false;
  if (!value) return false;
  try {
    return isPiiEnvelope(JSON.parse(value));
  } catch {
    return false;
  }
}

export function isLatestEncryptedPiiStoredValue(value: unknown): boolean {
  if (typeof value !== "string" || !value) return false;
  try {
    return isPiiEnvelopeV2(JSON.parse(value));
  } catch {
    return false;
  }
}

export function serializePiiValue(plaintext: string): { stored: string; encrypted: boolean } {
  if (plaintext === "") {
    return { stored: plaintext, encrypted: false };
  }

  const secret = getPiiEncryptionSecret();
  if (!secret) {
    return { stored: plaintext, encrypted: false };
  }

  const iv = crypto.randomBytes(12);
  const key = getStaticEncryptionKey(secret);
  const cipher = crypto.createCipheriv(PII_ENVELOPE_ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  const envelope: PiiEnvelopeV2 = {
    kind: PII_ENVELOPE_KIND,
    version: PII_ENVELOPE_VERSION_V2,
    algorithm: PII_ENVELOPE_ALGORITHM,
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };

  return {
    stored: JSON.stringify(envelope),
    encrypted: true,
  };
}

export function deserializePiiValue(stored: string): { plaintext: string; encrypted: boolean } {
  if (!stored) {
    return { plaintext: stored, encrypted: false };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(stored);
  } catch {
    return { plaintext: stored, encrypted: false };
  }

  if (!isPiiEnvelope(parsed)) {
    return { plaintext: stored, encrypted: false };
  }

  const secret = getPiiEncryptionSecret();
  if (!secret) {
    throw new Error("PII_ENCRYPTION_KEY is required to decrypt this value.");
  }

  const iv = requireBufferFromBase64(parsed.iv, "iv");
  const tag = requireBufferFromBase64(parsed.tag, "tag");
  const ciphertext = requireBufferFromBase64(parsed.ciphertext, "ciphertext");
  const key = isPiiEnvelopeV1(parsed)
    ? deriveEncryptionKey(secret, requireBufferFromBase64(parsed.salt, "salt"))
    : getStaticEncryptionKey(secret);
  const decipher = crypto.createDecipheriv(PII_ENVELOPE_ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");

  return {
    plaintext,
    encrypted: true,
  };
}

export function encryptNullableText(value: unknown): string | null | undefined | unknown {
  if (value === null || value === undefined) return value;
  if (typeof value !== "string") return value;
  return serializePiiValue(value).stored;
}

export function decryptNullableText(value: unknown): string | null | undefined | unknown {
  if (value === null || value === undefined) return value;
  if (typeof value !== "string") return value;
  return deserializePiiValue(value).plaintext;
}

export function encryptRecordFields<T extends Record<string, any>>(record: T, fields: readonly string[]): T {
  const next: Record<string, unknown> = { ...record };
  for (const field of fields) {
    if (!(field in next)) continue;
    next[field] = encryptNullableText(next[field]);
  }
  return next as T;
}

export function decryptRecordFields<T extends Record<string, any>>(record: T, fields: readonly string[]): T {
  const next: Record<string, unknown> = { ...record };
  for (const field of fields) {
    if (!(field in next)) continue;
    next[field] = decryptNullableText(next[field]);
  }
  return next as T;
}
