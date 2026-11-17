import {
  pgTable,
  uuid,
  text,
  timestamp,
  boolean,
  integer,
  bigint,
  pgEnum,
  index,
  uniqueIndex,
  jsonb,
} from "drizzle-orm/pg-core";

export const userRole = pgEnum("user_role", ["user", "admin"]);
export const userStatus = pgEnum("user_status", ["active", "suspended", "blocked"]);
export const driveMode = pgEnum("drive_mode", [
  "active",
  "read_only",
  "draining",
  "offline",
  "disabled",
]);
export const placementPolicy = pgEnum("placement_policy", [
  "fill_first",
  "most_free",
  "pinned",
]);

export const users = pgTable(
  "users",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    email: text("email").notNull(),
    passwordHash: text("password_hash").notNull(),
    role: userRole("role").notNull().default("user"),
    status: userStatus("status").notNull().default("active"),
    emailVerifiedAt: timestamp("email_verified_at", { withTimezone: true }),
    totpSecret: text("totp_secret"),
    totpEnabled: boolean("totp_enabled").notNull().default(false),
    quotaBytes: bigint("quota_bytes", { mode: "number" }).notNull().default(10 * 1024 * 1024 * 1024),
    usedBytes: bigint("used_bytes", { mode: "number" }).notNull().default(0),
    failedLogins: integer("failed_logins").notNull().default(0),
    lockedUntil: timestamp("locked_until", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("users_email_unique").on(t.email)],
);

export const sessions = pgTable(
  "sessions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull(),
    ip: text("ip"),
    userAgent: text("user_agent"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (t) => [
    uniqueIndex("sessions_token_hash_unique").on(t.tokenHash),
    index("sessions_user_idx").on(t.userId),
  ],
);

export const drives = pgTable(
  "drives",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    agentDriveId: text("agent_drive_id").notNull(),
    label: text("label").notNull(),
    root: text("root").notNull(),
    mode: driveMode("mode").notNull().default("active"),
    enabled: boolean("enabled").notNull().default(true),
    capacityBytes: bigint("capacity_bytes", { mode: "number" }).notNull().default(0),
    freeBytes: bigint("free_bytes", { mode: "number" }).notNull().default(0),
    placement: placementPolicy("placement").notNull().default("fill_first"),
    lastHeartbeatAt: timestamp("last_heartbeat_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("drives_agent_drive_unique").on(t.agentDriveId)],
);

export const files = pgTable(
  "files",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    ownerId: uuid("owner_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    driveId: uuid("drive_id").references(() => drives.id, { onDelete: "restrict" }),
    name: text("name").notNull(),
    mimeType: text("mime_type").notNull().default("application/octet-stream"),
    sizeBytes: bigint("size_bytes", { mode: "number" }).notNull().default(0),
    sha256: text("sha256"),
    status: text("status", { enum: ["uploading", "ready", "trashed", "deleted"] })
      .notNull()
      .default("uploading"),
    trashedAt: timestamp("trashed_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("files_owner_idx").on(t.ownerId, t.status)],
);

export const uploads = pgTable(
  "uploads",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    fileId: uuid("file_id")
      .notNull()
      .references(() => files.id, { onDelete: "cascade" }),
    ownerId: uuid("owner_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    expectedSize: bigint("expected_size", { mode: "number" }).notNull(),
    chunkSize: integer("chunk_size").notNull(),
    receivedBytes: bigint("received_bytes", { mode: "number" }).notNull().default(0),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  },
  (t) => [index("uploads_owner_idx").on(t.ownerId)],
);

export const shareLinks = pgTable(
  "share_links",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    fileId: uuid("file_id")
      .notNull()
      .references(() => files.id, { onDelete: "cascade" }),
    ownerId: uuid("owner_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("share_links_token_hash_unique").on(t.tokenHash)],
);

export const auditLog = pgTable(
  "audit_log",
  {
    id: bigint("id", { mode: "number" }).primaryKey().generatedByDefaultAsIdentity(),
    actorId: uuid("actor_id"),
    action: text("action").notNull(),
    target: text("target"),
    details: jsonb("details"),
    ip: text("ip"),
    prevHash: text("prev_hash").notNull(),
    hash: text("hash").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("audit_log_created_idx").on(t.createdAt)],
);

export const settings = pgTable("settings", {
  key: text("key").primaryKey(),
  value: jsonb("value").notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const rateLimits = pgTable(
  "rate_limits",
  {
    key: text("key").primaryKey(),
    count: integer("count").notNull().default(0),
    windowStart: timestamp("window_start", { withTimezone: true }).notNull().defaultNow(),
  },
);
