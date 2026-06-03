import express, { type Request, Response, NextFunction } from "express";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import { registerRoutes } from "./routes";
import { serveStatic } from "./static";
import { createServer } from "http";
import { seedDatabase } from "./seed";
import { ensureDatabasePerformanceObjects, pool } from "./db";
import { storage } from "./storage";
import { assertPiiEncryptionReadyForProduction } from "./pii-security";

const app = express();
const httpServer = createServer(app);

declare module "http" {
  interface IncomingMessage {
    rawBody: unknown;
  }
}

declare module "express-session" {
  interface SessionData {
    userId: string;
  }
}

app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  }),
);

app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.get("/api/healthz", (_req, res) => {
  res.json({
    ok: true,
    service: "crm-api",
    timestamp: new Date().toISOString(),
    uptimeSec: Math.round(process.uptime()),
  });
});

app.get("/api/readyz", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      ok: true,
      db: "up",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    res.status(503).json({
      ok: false,
      db: "down",
      message: "database connection failed",
      timestamp: new Date().toISOString(),
    });
  }
});

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);

app.disable("x-powered-by");

let cachedMaxLoginAttempts = 10;
let settingsCacheTime = 0;

async function getMaxLoginAttempts(): Promise<number> {
  const now = Date.now();
  if (now - settingsCacheTime > 60000) {
    try {
      const setting = await storage.getSystemSetting("max_login_attempts");
      if (setting) cachedMaxLoginAttempts = parseInt(setting.settingValue) || 10;
      settingsCacheTime = now;
    } catch {}
  }
  return cachedMaxLoginAttempts;
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: async () => await getMaxLoginAttempts(),
  message: { error: "로그인 시도가 너무 많습니다. 15분 후 다시 시도해주세요." },
  standardHeaders: true,
  legacyHeaders: false,
  validate: { xForwardedForHeader: false, ip: false },
});

const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 200,
  message: { error: "요청이 너무 많습니다. 잠시 후 다시 시도해주세요." },
  standardHeaders: true,
  legacyHeaders: false,
  validate: { xForwardedForHeader: false, ip: false },
});

app.use("/api/", apiLimiter);

const PgSession = connectPgSimple(session);

const runtimeNodeEnv = (process.env.NODE_ENV || "production").toLowerCase();
const isProduction = runtimeNodeEnv === "production";
const configuredSessionSecret = (process.env.SESSION_SECRET || "").trim();

function parseBooleanEnv(value?: string): boolean | undefined {
  const normalized = (value || "").trim().toLowerCase();
  if (!normalized) return undefined;
  if (["1", "true", "yes", "y", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "n", "off"].includes(normalized)) return false;
  return undefined;
}

function resolveTrustProxyValue(rawValue: string | undefined): string | number | boolean {
  const trimmed = (rawValue || "").trim();
  if (!trimmed) return isProduction ? 1 : false;

  const boolValue = parseBooleanEnv(trimmed);
  if (boolValue !== undefined) return boolValue ? 1 : false;

  const parsed = Number.parseInt(trimmed, 10);
  if (Number.isFinite(parsed) && parsed >= 0) return parsed;

  return trimmed;
}

function resolveCookieSecure(rawValue: string | undefined): boolean | "auto" {
  const normalized = (rawValue || "").trim().toLowerCase();
  if (!normalized) return isProduction ? "auto" : false;
  if (normalized === "auto") return "auto";
  const boolValue = parseBooleanEnv(normalized);
  if (boolValue !== undefined) return boolValue;
  return isProduction ? "auto" : false;
}

function resolveCookieSameSite(rawValue: string | undefined): "lax" | "strict" | "none" {
  const normalized = (rawValue || "").trim().toLowerCase();
  if (normalized === "strict" || normalized === "none" || normalized === "lax") return normalized;
  return "lax";
}

function shouldSeedOnBoot(): boolean {
  const explicit = parseBooleanEnv(process.env.SEED_ON_BOOT);
  if (explicit !== undefined) return explicit;
  return !isProduction;
}

const SESSION_TIMEOUT_DEFAULT_MIN = 5;
const SESSION_TIMEOUT_DEFAULT_MAX = 24 * 60;

function clampSessionTimeoutMinutes(value: number): number {
  if (!Number.isFinite(value)) return 30;
  if (value < SESSION_TIMEOUT_DEFAULT_MIN) return SESSION_TIMEOUT_DEFAULT_MIN;
  if (value > SESSION_TIMEOUT_DEFAULT_MAX) return SESSION_TIMEOUT_DEFAULT_MAX;
  return Math.floor(value);
}

const trustProxyValue = resolveTrustProxyValue(process.env.TRUST_PROXY);
if (trustProxyValue !== false) {
  app.set("trust proxy", trustProxyValue);
}

if (isProduction && !configuredSessionSecret) {
  throw new Error("SESSION_SECRET must be set in production.");
}

assertPiiEncryptionReadyForProduction();

const sessionCookieName = (process.env.SESSION_COOKIE_NAME || "crm.sid").trim() || "crm.sid";
const sessionCookieSecure = resolveCookieSecure(process.env.SESSION_COOKIE_SECURE);
const sessionCookieSameSite = resolveCookieSameSite(process.env.SESSION_COOKIE_SAMESITE);
const sessionCookieDomain = (process.env.SESSION_COOKIE_DOMAIN || "").trim() || undefined;
const defaultSessionTimeoutMinutes = clampSessionTimeoutMinutes(
  Number.parseInt(process.env.SESSION_TIMEOUT_DEFAULT_MINUTES || "30", 10),
);
const sessionPruneInterval = Math.max(
  60,
  Number.parseInt(process.env.SESSION_PRUNE_INTERVAL_SECONDS || "900", 10) || 900,
);

app.use(
  session({
    name: sessionCookieName,
    store: new PgSession({
      pool,
      tableName: "session",
      createTableIfMissing: true,
      pruneSessionInterval: sessionPruneInterval,
    }),
    secret: configuredSessionSecret || "crm-dev-session-secret",
    resave: false,
    saveUninitialized: false,
    proxy: trustProxyValue !== false,
    rolling: true,
    cookie: {
      maxAge: 30 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: sessionCookieSecure,
      sameSite: sessionCookieSameSite,
      domain: sessionCookieDomain,
    },
  })
);

let cachedSessionTimeout = defaultSessionTimeoutMinutes;
let sessionTimeoutCacheTime = 0;

app.use(async (req, _res, next) => {
  if (req.session && req.session.cookie) {
    const now = Date.now();
    if (now - sessionTimeoutCacheTime > 60000) {
      try {
        const setting = await storage.getSystemSetting("session_timeout");
        if (setting) {
          cachedSessionTimeout = clampSessionTimeoutMinutes(parseInt(setting.settingValue, 10));
        }
        sessionTimeoutCacheTime = now;
      } catch {}
    }
    req.session.cookie.maxAge = cachedSessionTimeout * 60 * 1000;
  }
  next();
});

export function log(message: string, source = "express") {
  const formattedTime = new Date().toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });

  console.log(`${formattedTime} [${source}] ${message}`);
}

function maskName(value: string) {
  const chars = Array.from(String(value || "").trim());
  if (chars.length === 0) return "";
  if (chars.length === 1) return "*";
  if (chars.length === 2) return `${chars[0]}*`;
  return `${chars[0]}${"*".repeat(chars.length - 2)}${chars[chars.length - 1]}`;
}

function maskEmail(value: string) {
  const text = String(value || "").trim();
  const atIndex = text.indexOf("@");
  if (atIndex <= 1) return "***";
  return `${text.slice(0, 1)}***${text.slice(atIndex)}`;
}

function maskPhone(value: string) {
  const digits = String(value || "").replace(/\D/g, "");
  if (digits.length <= 4) return "*".repeat(digits.length || 1);
  return `${digits.slice(0, 3)}****${digits.slice(-4)}`;
}

function maskIdentifier(value: string) {
  const text = String(value || "").trim();
  if (text.length <= 4) return "*".repeat(text.length || 1);
  return `${"*".repeat(Math.max(0, text.length - 4))}${text.slice(-4)}`;
}

function maskIpAddress(value: string) {
  const text = String(value || "").trim();
  if (text.includes(".")) {
    const parts = text.split(".");
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.*.*`;
    }
  }
  if (text.includes(":")) {
    const parts = text.split(":").filter(Boolean);
    if (parts.length >= 2) {
      return `${parts.slice(0, 2).join(":")}::*`;
    }
  }
  return "***";
}

function maskAddress(value: string) {
  const text = String(value || "").trim();
  if (!text) return "";
  return `${text.slice(0, Math.min(6, text.length))}...`;
}

function summarizeText(value: string) {
  const text = String(value || "").trim();
  if (!text) return "";
  return `[REDACTED_TEXT:${text.length}]`;
}

function sanitizeApiLogValue(value: unknown, key = ""): unknown {
  if (value === null || value === undefined) return value;

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeApiLogValue(item, key));
  }

  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([childKey, childValue]) => [
        childKey,
        sanitizeApiLogValue(childValue, childKey),
      ]),
    );
  }

  if (typeof value !== "string") {
    return value;
  }

  const normalizedKey = key.replace(/[^a-z0-9]/gi, "").toLowerCase();

  if (
    ["password", "sessionid", "secret", "token", "authorization", "cookie", "userdata", "rawdata", "filedata"].includes(
      normalizedKey,
    )
  ) {
    return "[REDACTED]";
  }

  if (normalizedKey.includes("email")) return maskEmail(value);
  if (normalizedKey.includes("phone") || normalizedKey.includes("fax") || normalizedKey.endsWith("tel")) {
    return maskPhone(value);
  }
  if (normalizedKey.includes("ipaddress")) return maskIpAddress(value);
  if (normalizedKey.includes("address")) return maskAddress(value);
  if (normalizedKey === "loginid" || normalizedKey === "userid" || normalizedKey.endsWith("userid")) {
    return maskIdentifier(value);
  }
  if (normalizedKey.includes("account") || normalizedKey.includes("businessnumber")) return maskIdentifier(value);
  if (normalizedKey.includes("customername") || normalizedKey.includes("username") || normalizedKey.includes("authorname") || normalizedKey.includes("depositorname") || normalizedKey.includes("createdbyname") || normalizedKey === "name") {
    return maskName(value);
  }
  if (normalizedKey.includes("content") || normalizedKey.includes("description") || normalizedKey.includes("notes") || normalizedKey.includes("details")) {
    return summarizeText(value);
  }

  return value;
}

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        const sanitized = sanitizeApiLogValue(capturedJsonResponse);
        const logStr = JSON.stringify(sanitized);
        if (logStr.length > 500) {
          logLine += ` :: ${logStr.substring(0, 500)}...[truncated]`;
        } else {
          logLine += ` :: ${logStr}`;
        }
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  await registerRoutes(httpServer, app);

  app.use((err: any, _req: Request, res: Response, next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    console.error("Internal Server Error:", err);

    if (res.headersSent) {
      return next(err);
    }

    return res.status(status).json({ message });
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (isProduction) {
    const shouldServeStatic = process.env.SERVE_STATIC !== "false";
    if (shouldServeStatic) {
      serveStatic(app);
    } else {
      log("static serving is disabled (SERVE_STATIC=false)");
    }
  } else {
    const { setupVite } = await import("./vite");
    await setupVite(httpServer, app);
  }

  // ALWAYS serve the app on the port specified in the environment variable PORT
  // Other ports are firewalled. Default to 5000 if not specified.
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
  const port = parseInt(process.env.PORT || "5000", 10);
  httpServer.listen(
    {
      port,
      host: "0.0.0.0",
      reusePort: process.platform !== "win32",
    },
    () => {
      log(`serving on port ${port}`);
      void runPostListenStartupTasks();
    },
  );
})();

async function runPostListenStartupTasks() {
  await ensureDatabasePerformanceObjects();

  try {
    if (shouldSeedOnBoot()) {
      await seedDatabase();
    } else {
      log("database seed skipped on boot");
    }
  } catch (error) {
    console.error("Error seeding database:", error);
  }
}
