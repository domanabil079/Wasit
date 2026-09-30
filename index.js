"use strict";
const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const app = express();
const IS_PROD = process.env.NODE_ENV === "production" || !!process.env.VERCEL;
const SESSION_DAYS = Math.max(1, Math.min(30, Number(process.env.SESSION_DAYS || 1)));
if (!process.env.DATABASE_URL) console.warn("DATABASE_URL is missing. Connect Neon/Postgres before using the API.");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : undefined,
  max: Number(process.env.DB_POOL_MAX || 5),
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 10000
});

app.disable("x-powered-by");
app.set("trust proxy", Number(process.env.TRUST_PROXY || 1));
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  if (IS_PROD) res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  if (req.path.startsWith("/api/")) res.setHeader("Cache-Control", "no-store");
  next();
});
app.use(express.json({ limit: "250kb" }));
app.use(express.urlencoded({ extended: false, limit: "50kb" }));

let schemaPromise;
async function ensureSchema() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is not configured");
  if (!schemaPromise) schemaPromise = pool.query(`
CREATE TABLE IF NOT EXISTS admins (
 id BIGSERIAL PRIMARY KEY,
