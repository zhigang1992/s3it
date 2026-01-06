#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
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
const MULTIPART_THRESHOLD = 100 * 1024 * 1024; // 100MB - use multipart for files larger than this
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

  // Create canonical URI (URL-encode each path segment)
  const canonicalUri = url.pathname
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");

  // Create canonical query string (sorted by parameter name)
  const params = new URLSearchParams(url.search);
  const sortedParams = Array.from(params.entries()).sort((a, b) =>
    a[0].localeCompare(b[0])
  );
  const canonicalQuerystring = sortedParams
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join("&");

  // Hash the payload
  const payloadHash = createHash("sha256")
    .update(typeof payload === "string" ? payload : payload)
    .digest("hex");

  // Add required headers (lowercase keys for signing)
  const signedHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    signedHeaders[k.toLowerCase()] = v;
  }
  signedHeaders["host"] = url.host;
  signedHeaders["x-amz-date"] = amzDate;
  signedHeaders["x-amz-content-sha256"] = payloadHash;

  // Create sorted header list
  const sortedHeaderKeys = Object.keys(signedHeaders).sort();
  const canonicalHeaders =
    sortedHeaderKeys.map((k) => `${k}:${signedHeaders[k].trim()}`).join("\n") +
    "\n";
  const signedHeadersStr = sortedHeaderKeys.join(";");

  // Create canonical request
  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQuerystring,
    canonicalHeaders,
    signedHeadersStr,
    payloadHash,
  ].join("\n");

  // Create string to sign
  const algorithm = "AWS4-HMAC-SHA256";
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    algorithm,
    amzDate,
    credentialScope,
    createHash("sha256").update(canonicalRequest).digest("hex"),
  ].join("\n");

  // Calculate signature
  const signingKey = getSignatureKey(secretKey, dateStamp, region, service);
  const signature = createHmac("sha256", signingKey)
    .update(stringToSign)
    .digest("hex");

  // Create authorization header
  const authorizationHeader = `${algorithm} Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeadersStr}, Signature=${signature}`;

  // Return headers with original casing for HTTP request
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

// MIME type detection from file extension
function detectContentType(filePath: string): string {
  const ext = extname(filePath).toLowerCase();
  const mimeMap: Record<string, string> = {
    // Images
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

    // Documents
    ".pdf": "application/pdf",
    ".doc": "application/msword",
    ".docx":
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xls": "application/vnd.ms-excel",
    ".xlsx":
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".ppt": "application/vnd.ms-powerpoint",
    ".pptx":
      "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".odt": "application/vnd.oasis.opendocument.text",
    ".ods": "application/vnd.oasis.opendocument.spreadsheet",
    ".odp": "application/vnd.oasis.opendocument.presentation",

    // Text
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
    ".toml": "text/plain",

    // Archives
    ".zip": "application/zip",
    ".tar": "application/x-tar",
    ".gz": "application/gzip",
    ".tgz": "application/gzip",
    ".bz2": "application/x-bzip2",
    ".xz": "application/x-xz",
    ".7z": "application/x-7z-compressed",
    ".rar": "application/vnd.rar",

    // Audio
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".ogg": "audio/ogg",
    ".m4a": "audio/mp4",
    ".flac": "audio/flac",
    ".aac": "audio/aac",
    ".wma": "audio/x-ms-wma",

    // Video
    ".mp4": "video/mp4",
    ".avi": "video/x-msvideo",
    ".mov": "video/quicktime",
    ".wmv": "video/x-ms-wmv",
    ".webm": "video/webm",
    ".mkv": "video/x-matroska",
    ".flv": "video/x-flv",
    ".m4v": "video/x-m4v",

    // Code
    ".ts": "text/typescript",
    ".tsx": "text/typescript",
    ".jsx": "text/javascript",
    ".py": "text/x-python",
    ".java": "text/x-java",
    ".c": "text/x-c",
    ".cpp": "text/x-c++",
    ".h": "text/x-c",
    ".hpp": "text/x-c++",
    ".rs": "text/x-rust",
    ".go": "text/x-go",
    ".rb": "text/x-ruby",
    ".php": "text/x-php",
    ".swift": "text/x-swift",
    ".kt": "text/x-kotlin",
    ".scala": "text/x-scala",
    ".sh": "text/x-shellscript",
    ".bash": "text/x-shellscript",
    ".zsh": "text/x-shellscript",
    ".sql": "text/x-sql",

    // Fonts
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".otf": "font/otf",
    ".eot": "application/vnd.ms-fontobject",

    // Other
    ".wasm": "application/wasm",
    ".bin": "application/octet-stream",
    ".exe": "application/octet-stream",
    ".dll": "application/octet-stream",
    ".so": "application/octet-stream",
    ".dylib": "application/octet-stream",
  };

  return mimeMap[ext] || "application/octet-stream";
}

class UploadFileServer {
  private server: Server;

  constructor() {
    this.server = new Server(
      {
        name: "s3it",
        version: "1.0.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupToolHandlers();
  }

  private setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: "upload",
            description:
              "Upload a file to cloud storage. Returns just the URL. Auto-detects content type from file extension. Uses multipart upload for files > 100MB.",
            inputSchema: {
              type: "object",
              properties: {
                file: {
                  type: "string",
                  description: "Path to the file to upload",
                },
              },
              required: ["file"],
            },
          },
        ],
      };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      if (request.params.name === "upload") {
        return this.handleUpload(request.params.arguments as { file: string });
      }

      throw new McpError(
        ErrorCode.MethodNotFound,
        `Unknown tool: ${request.params.name}`
      );
    });
  }

  // Initiate multipart upload
  private async initiateMultipartUpload(
    remotePath: string,
    contentType: string
  ): Promise<string> {
    const url = new URL(`${S3_ENDPOINT}/${S3_BUCKET}/${remotePath}?uploads`);
    const headers = signRequest(
      "POST",
      url,
      { "Content-Type": contentType },
      "",
      S3_ACCESS_KEY,
      S3_SECRET_KEY,
      S3_REGION
    );

    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `Failed to initiate multipart upload: ${response.status} ${errorText}`
      );
    }

    const responseText = await response.text();
    const uploadIdMatch = responseText.match(/<UploadId>(.+?)<\/UploadId>/);
    if (!uploadIdMatch) {
      throw new Error("Failed to parse UploadId from response");
    }
    return uploadIdMatch[1];
  }

  // Upload a single part
  private async uploadPart(
    remotePath: string,
    uploadId: string,
    partNumber: number,
    data: Buffer
  ): Promise<string> {
    const url = new URL(
      `${S3_ENDPOINT}/${S3_BUCKET}/${remotePath}?partNumber=${partNumber}&uploadId=${encodeURIComponent(uploadId)}`
    );
    const headers = signRequest(
      "PUT",
      url,
      { "Content-Length": String(data.length) },
      data,
      S3_ACCESS_KEY,
      S3_SECRET_KEY,
      S3_REGION
    );

    const response = await fetch(url.toString(), {
      method: "PUT",
      headers,
      body: data,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `Failed to upload part ${partNumber}: ${response.status} ${errorText}`
      );
    }

    const etag = response.headers.get("ETag");
    if (!etag) {
      throw new Error(`No ETag returned for part ${partNumber}`);
    }
    return etag;
  }

  // Complete multipart upload
  private async completeMultipartUpload(
    remotePath: string,
    uploadId: string,
    parts: Array<{ partNumber: number; etag: string }>
  ): Promise<void> {
    const url = new URL(
      `${S3_ENDPOINT}/${S3_BUCKET}/${remotePath}?uploadId=${encodeURIComponent(uploadId)}`
    );

    const partsXml = parts
      .map(
        (p) =>
          `<Part><PartNumber>${p.partNumber}</PartNumber><ETag>${p.etag}</ETag></Part>`
      )
      .join("");
    const body = `<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUpload>${partsXml}</CompleteMultipartUpload>`;

    const headers = signRequest(
      "POST",
      url,
      { "Content-Type": "application/xml" },
      body,
      S3_ACCESS_KEY,
      S3_SECRET_KEY,
      S3_REGION
    );

    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `Failed to complete multipart upload: ${response.status} ${errorText}`
      );
    }
  }

  // Abort multipart upload (cleanup on failure)
  private async abortMultipartUpload(
    remotePath: string,
    uploadId: string
  ): Promise<void> {
    const url = new URL(
      `${S3_ENDPOINT}/${S3_BUCKET}/${remotePath}?uploadId=${encodeURIComponent(uploadId)}`
    );
    const headers = signRequest(
      "DELETE",
      url,
      {},
      "",
      S3_ACCESS_KEY,
      S3_SECRET_KEY,
      S3_REGION
    );

    await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });
  }

  // Simple PUT upload for small files
  private async simpleUpload(
    remotePath: string,
    data: Buffer,
    contentType: string
  ): Promise<void> {
    const url = new URL(`${S3_ENDPOINT}/${S3_BUCKET}/${remotePath}`);
    const headers = signRequest(
      "PUT",
      url,
      { "Content-Type": contentType, "Content-Length": String(data.length) },
      data,
      S3_ACCESS_KEY,
      S3_SECRET_KEY,
      S3_REGION
    );

    const response = await fetch(url.toString(), {
      method: "PUT",
      headers,
      body: data,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Upload failed: ${response.status} ${errorText}`);
    }
  }

  // Read a chunk from file
  private async readFileChunk(
    filePath: string,
    start: number,
    length: number
  ): Promise<Buffer> {
    const handle = await fs.open(filePath, "r");
    try {
      const buffer = Buffer.alloc(length);
      const { bytesRead } = await handle.read(buffer, 0, length, start);
      return buffer.subarray(0, bytesRead);
    } finally {
      await handle.close();
    }
  }

  // Upload file with automatic multipart handling
  private async uploadToS3(
    filePath: string,
    remotePath: string,
    contentType: string
  ): Promise<void> {
    const stats = await fs.stat(filePath);
    const fileSize = stats.size;

    if (fileSize <= MULTIPART_THRESHOLD) {
      const data = await fs.readFile(filePath);
      await this.simpleUpload(remotePath, data, contentType);
      return;
    }

    // Use multipart upload for large files
    console.error(
      `Multipart upload: ${(fileSize / 1024 / 1024).toFixed(2)} MB`
    );

    const uploadId = await this.initiateMultipartUpload(remotePath, contentType);
    const parts: Array<{ partNumber: number; etag: string }> = [];

    try {
      const totalParts = Math.ceil(fileSize / PART_SIZE);

      for (let partNumber = 1; partNumber <= totalParts; partNumber++) {
        const start = (partNumber - 1) * PART_SIZE;
        const bytesToRead = Math.min(PART_SIZE, fileSize - start);

        console.error(`Part ${partNumber}/${totalParts}`);

        const chunkBuffer = await this.readFileChunk(
          filePath,
          start,
          bytesToRead
        );
        const etag = await this.uploadPart(
          remotePath,
          uploadId,
          partNumber,
          chunkBuffer
        );
        parts.push({ partNumber, etag });
      }

      await this.completeMultipartUpload(remotePath, uploadId, parts);
    } catch (error) {
      console.error(`Upload failed, cleaning up`);
      await this.abortMultipartUpload(remotePath, uploadId);
      throw error;
    }
  }

  private async handleUpload(args: { file: string }) {
    const { file } = args;

    if (!file) {
      throw new McpError(ErrorCode.InvalidParams, "file is required");
    }

    try {
      // Check if file exists
      try {
        await fs.access(file);
      } catch {
        throw new McpError(ErrorCode.InvalidParams, `File not found: ${file}`);
      }

      // Generate UUID folder and preserve original filename
      const folderId = randomUUID();
      const originalFileName = basename(file);
      const remotePath = `${folderId}/${originalFileName}`;

      // Detect content type
      const contentType = detectContentType(file);

      // Upload to S3
      await this.uploadToS3(file, remotePath, contentType);

      const publicUrl = `${S3_ENDPOINT}/${S3_BUCKET}/${remotePath}`;

      // Return just the URL for terminal-style simplicity
      return {
        content: [
          {
            type: "text",
            text: publicUrl,
          },
        ],
      };
    } catch (error) {
      if (error instanceof McpError) {
        throw error;
      }
      throw new McpError(
        ErrorCode.InternalError,
        `Upload failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error("s3it ready");
  }
}

const server = new UploadFileServer();
server.run().catch(console.error);
