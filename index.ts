#!/usr/bin/env node
import { basename, extname } from "node:path";
import { randomUUID, createHash, createHmac } from "node:crypto";
import { promises as fs } from "node:fs";

// S3 configuration from environment (defaults to reily.app public bucket)
const S3_ENDPOINT = process.env.S3_ENDPOINT || "https://s3.reily.app";
const S3_BUCKET = process.env.S3_BUCKET || "public";
const S3_ACCESS_KEY = process.env.S3_ACCESS_KEY || "bhEJaGR0UGgmZtxEi2yY";
const S3_SECRET_KEY =
  process.env.S3_SECRET_KEY || "lE1fn0FdAAhQwFLnumJt0th0Q2j684h4v8EIQdzy";
const S3_REGION = process.env.S3_REGION || "auto";

// Multipart upload settings
const MULTIPART_THRESHOLD = 100 * 1024 * 1024; // 100MB
const PART_SIZE = 100 * 1024 * 1024; // 100MB per part

// AWS Signature V4 signing utilities
function getSignatureKey(
  key: string,
  dateStamp: string,
  region: string,
  service: string
): Buffer {
  const kDate = createHmac("sha256", `AWS4${key}`).update(dateStamp).digest();
  const kRegion = createHmac("sha256", kDate).update(region).digest();
  const kService = createHmac("sha256", kRegion).update(service).digest();
  const kSigning = createHmac("sha256", kService)
    .update("aws4_request")
    .digest();
  return kSigning;
}

function signRequest(
  method: string,
  url: URL,
  headers: Record<string, string>,
  payload: Buffer | string,
  accessKey: string,
  secretKey: string,
  region: string
): Record<string, string> {
  const service = "s3";
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);

  // Use the already-encoded pathname from the URL object
  // The URL constructor already properly encodes the path
  const canonicalUri = url.pathname;

  const params = new URLSearchParams(url.search);
  const sortedParams = Array.from(params.entries()).sort((a, b) =>
    a[0].localeCompare(b[0])
  );
  const canonicalQuerystring = sortedParams
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join("&");

  const payloadHash = createHash("sha256")
    .update(typeof payload === "string" ? payload : payload)
    .digest("hex");

  const signedHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    signedHeaders[k.toLowerCase()] = v;
  }
  signedHeaders["host"] = url.host;
  signedHeaders["x-amz-date"] = amzDate;
  signedHeaders["x-amz-content-sha256"] = payloadHash;

  const sortedHeaderKeys = Object.keys(signedHeaders).sort();
  const canonicalHeaders =
    sortedHeaderKeys.map((k) => `${k}:${signedHeaders[k].trim()}`).join("\n") +
    "\n";
  const signedHeadersStr = sortedHeaderKeys.join(";");

  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQuerystring,
    canonicalHeaders,
    signedHeadersStr,
    payloadHash,
  ].join("\n");

  const algorithm = "AWS4-HMAC-SHA256";
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    algorithm,
    amzDate,
    credentialScope,
    createHash("sha256").update(canonicalRequest).digest("hex"),
  ].join("\n");

  const signingKey = getSignatureKey(secretKey, dateStamp, region, service);
  const signature = createHmac("sha256", signingKey)
    .update(stringToSign)
    .digest("hex");

  const authorizationHeader = `${algorithm} Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeadersStr}, Signature=${signature}`;

  const resultHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    resultHeaders[k] = v;
  }
  resultHeaders["Host"] = url.host;
  resultHeaders["X-Amz-Date"] = amzDate;
  resultHeaders["X-Amz-Content-Sha256"] = payloadHash;
  resultHeaders["Authorization"] = authorizationHeader;

  return resultHeaders;
}

function detectContentType(filePath: string): string {
  const ext = extname(filePath).toLowerCase();
  const mimeMap: Record<string, string> = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
    ".bmp": "image/bmp",
    ".ico": "image/x-icon",
    ".tiff": "image/tiff",
    ".tif": "image/tiff",
    ".avif": "image/avif",
    ".heic": "image/heic",
    ".heif": "image/heif",
    ".pdf": "application/pdf",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xls": "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".ppt": "application/vnd.ms-powerpoint",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".txt": "text/plain",
    ".html": "text/html",
    ".htm": "text/html",
    ".css": "text/css",
    ".js": "text/javascript",
    ".mjs": "text/javascript",
    ".json": "application/json",
    ".xml": "application/xml",
    ".csv": "text/csv",
    ".md": "text/markdown",
    ".yaml": "text/yaml",
    ".yml": "text/yaml",
    ".zip": "application/zip",
    ".tar": "application/x-tar",
    ".gz": "application/gzip",
    ".tgz": "application/gzip",
    ".7z": "application/x-7z-compressed",
    ".rar": "application/vnd.rar",
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".ogg": "audio/ogg",
    ".m4a": "audio/mp4",
    ".flac": "audio/flac",
    ".mp4": "video/mp4",
    ".avi": "video/x-msvideo",
    ".mov": "video/quicktime",
    ".wmv": "video/x-ms-wmv",
    ".webm": "video/webm",
    ".mkv": "video/x-matroska",
    ".ts": "text/typescript",
    ".tsx": "text/typescript",
    ".jsx": "text/javascript",
    ".py": "text/x-python",
    ".java": "text/x-java",
    ".c": "text/x-c",
    ".cpp": "text/x-c++",
    ".rs": "text/x-rust",
    ".go": "text/x-go",
    ".rb": "text/x-ruby",
    ".php": "text/x-php",
    ".sh": "text/x-shellscript",
    ".sql": "text/x-sql",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".otf": "font/otf",
    ".wasm": "application/wasm",
  };
  return mimeMap[ext] || "application/octet-stream";
}

async function initiateMultipartUpload(remotePath: string, contentType: string): Promise<string> {
  const url = new URL(`${S3_ENDPOINT}/${S3_BUCKET}/${remotePath}?uploads`);
  const headers = signRequest("POST", url, { "Content-Type": contentType }, "", S3_ACCESS_KEY, S3_SECRET_KEY, S3_REGION);

  const response = await fetch(url.toString(), { method: "POST", headers });
  if (!response.ok) {
    throw new Error(`Failed to initiate multipart upload: ${response.status}`);
  }

  const responseText = await response.text();
  const uploadIdMatch = responseText.match(/<UploadId>(.+?)<\/UploadId>/);
  if (!uploadIdMatch) throw new Error("Failed to parse UploadId");
  return uploadIdMatch[1];
}

async function uploadPart(remotePath: string, uploadId: string, partNumber: number, data: Buffer): Promise<string> {
  const url = new URL(`${S3_ENDPOINT}/${S3_BUCKET}/${remotePath}?partNumber=${partNumber}&uploadId=${encodeURIComponent(uploadId)}`);
  const headers = signRequest("PUT", url, { "Content-Length": String(data.length) }, data, S3_ACCESS_KEY, S3_SECRET_KEY, S3_REGION);

  const response = await fetch(url.toString(), { method: "PUT", headers, body: data });
  if (!response.ok) {
    throw new Error(`Failed to upload part ${partNumber}: ${response.status}`);
  }

  const etag = response.headers.get("ETag");
  if (!etag) throw new Error(`No ETag for part ${partNumber}`);
  return etag;
}

async function completeMultipartUpload(remotePath: string, uploadId: string, parts: Array<{ partNumber: number; etag: string }>): Promise<void> {
  const url = new URL(`${S3_ENDPOINT}/${S3_BUCKET}/${remotePath}?uploadId=${encodeURIComponent(uploadId)}`);
  const partsXml = parts.map((p) => `<Part><PartNumber>${p.partNumber}</PartNumber><ETag>${p.etag}</ETag></Part>`).join("");
  const body = `<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUpload>${partsXml}</CompleteMultipartUpload>`;
  const headers = signRequest("POST", url, { "Content-Type": "application/xml" }, body, S3_ACCESS_KEY, S3_SECRET_KEY, S3_REGION);

  const response = await fetch(url.toString(), { method: "POST", headers, body });
  if (!response.ok) {
    throw new Error(`Failed to complete multipart upload: ${response.status}`);
  }
}

async function abortMultipartUpload(remotePath: string, uploadId: string): Promise<void> {
  const url = new URL(`${S3_ENDPOINT}/${S3_BUCKET}/${remotePath}?uploadId=${encodeURIComponent(uploadId)}`);
  const headers = signRequest("DELETE", url, {}, "", S3_ACCESS_KEY, S3_SECRET_KEY, S3_REGION);
  await fetch(url.toString(), { method: "DELETE", headers });
}

async function simpleUpload(remotePath: string, data: Buffer, contentType: string): Promise<void> {
  const url = new URL(`${S3_ENDPOINT}/${S3_BUCKET}/${remotePath}`);
  const headers = signRequest("PUT", url, { "Content-Type": contentType, "Content-Length": String(data.length) }, data, S3_ACCESS_KEY, S3_SECRET_KEY, S3_REGION);

  const response = await fetch(url.toString(), { method: "PUT", headers, body: data });
  if (!response.ok) {
    throw new Error(`Upload failed: ${response.status}`);
  }
}

async function readFileChunk(filePath: string, start: number, length: number): Promise<Buffer> {
  const handle = await fs.open(filePath, "r");
  try {
    const buffer = Buffer.alloc(length);
    const { bytesRead } = await handle.read(buffer, 0, length, start);
    return buffer.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
}

async function uploadFile(filePath: string): Promise<string> {
  // Check file exists
  try {
    await fs.access(filePath);
  } catch {
    throw new Error(`File not found: ${filePath}`);
  }

  const stats = await fs.stat(filePath);
  const fileSize = stats.size;
  const folderId = randomUUID();
  const originalFileName = basename(filePath);
  const remotePath = `${folderId}/${originalFileName}`;
  const contentType = detectContentType(filePath);

  if (fileSize <= MULTIPART_THRESHOLD) {
    const data = await fs.readFile(filePath);
    await simpleUpload(remotePath, data, contentType);
  } else {
    // Multipart upload
    process.stderr.write(`Uploading ${(fileSize / 1024 / 1024).toFixed(1)}MB...\n`);
    const uploadId = await initiateMultipartUpload(remotePath, contentType);
    const parts: Array<{ partNumber: number; etag: string }> = [];

    try {
      const totalParts = Math.ceil(fileSize / PART_SIZE);
      for (let partNumber = 1; partNumber <= totalParts; partNumber++) {
        const start = (partNumber - 1) * PART_SIZE;
        const bytesToRead = Math.min(PART_SIZE, fileSize - start);
        process.stderr.write(`Part ${partNumber}/${totalParts}\n`);
        const chunkBuffer = await readFileChunk(filePath, start, bytesToRead);
        const etag = await uploadPart(remotePath, uploadId, partNumber, chunkBuffer);
        parts.push({ partNumber, etag });
      }
      await completeMultipartUpload(remotePath, uploadId, parts);
    } catch (error) {
      await abortMultipartUpload(remotePath, uploadId);
      throw error;
    }
  }

  return `${S3_ENDPOINT}/${S3_BUCKET}/${remotePath}`;
}

// Main
const file = process.argv[2];

if (!file) {
  console.error("Usage: s3it <file>");
  process.exit(1);
}

uploadFile(file)
  .then((url) => console.log(url))
  .catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
