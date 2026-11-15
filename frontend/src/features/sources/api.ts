import { api, binaryApi } from "../../api/client";
import { toApiError, throwIfApiError } from "../../api/errors";
import type { components } from "../../api/schema";

export type ConsentVersion = components["schemas"]["ConsentCurrentVersionResponse"];
export type ConsentState = components["schemas"]["ConsentStateResponse"];
export type SourceRecord = components["schemas"]["SourceResponse"];
export type SourceKind = components["schemas"]["TextSourceCreate"]["kind"];
export type OwnershipMethod =
  components["schemas"]["OwnershipChallengeRequest"]["method"];
export type OwnershipChallenge = components["schemas"]["OwnershipChallengeResponse"];

export type SourceFileExtension = "txt" | "pdf" | "docx";
export type SourceFileKind = "FILE" | "PLATFORM_EXPORT";

const fileContentTypes: Record<SourceFileExtension, string> = {
  txt: "text/plain",
  pdf: "application/pdf",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
};

export async function getConsentVersion(): Promise<ConsentVersion> {
  const result = await api.GET("/v1/consent/current-version");
  return throwIfApiError(result);
}

export async function getConsentState(): Promise<ConsentState> {
  const result = await api.GET("/v1/consent/current");
  return throwIfApiError(result);
}

export async function acceptConsent(version: string): Promise<ConsentState> {
  const result = await api.POST("/v1/consent/accept", {
    body: { version, accepted: true },
  });
  return throwIfApiError(result);
}

export async function listSources(
  offset: number,
): Promise<components["schemas"]["SourceListResponse"]> {
  const result = await api.GET("/v1/sources", {
    params: { query: { limit: 100, offset } },
  });
  return throwIfApiError(result);
}

export async function createUrlSource(label: string, uri: string): Promise<SourceRecord> {
  const result = await api.POST("/v1/sources", {
    body: { kind: "URL", label, uri },
  });
  return throwIfApiError(result);
}

export async function createTextSource(
  kind: SourceKind,
  label: string,
  content: string,
): Promise<SourceRecord> {
  const result = await api.POST("/v1/sources", {
    body: { kind, label, content },
  });
  return throwIfApiError(result);
}

export async function uploadSourceFile(
  file: File,
  label: string,
  extension: SourceFileExtension,
  kind: SourceFileKind,
): Promise<SourceRecord> {
  const result = await binaryApi.POST("/v1/sources/file", {
    body: file,
    bodySerializer: (body) => body,
    params: {
      header: {
        "X-Source-Label": encodeURIComponent(label),
        "X-Source-Extension": extension,
        "X-Source-Kind": kind,
      },
    },
    headers: { "Content-Type": fileContentTypes[extension] },
  });
  return throwIfApiError(result);
}

export async function deleteSource(sourceId: string): Promise<void> {
  const result = await api.DELETE("/v1/sources/{source_id}", {
    params: { path: { source_id: sourceId } },
  });
  if ("error" in result) {
    throw toApiError(result.response, result.error);
  }
}

export async function createOwnershipChallenge(
  sourceId: string,
  method: OwnershipMethod,
  email?: string,
): Promise<OwnershipChallenge> {
  const result = await api.POST("/v1/sources/{source_id}/ownership/challenge", {
    params: { path: { source_id: sourceId } },
    body: email === undefined ? { method } : { method, email },
  });
  return throwIfApiError(result);
}

export async function verifyOwnership(
  sourceId: string,
  challengeId: string,
  proof: string | null,
): Promise<components["schemas"]["OwnershipVerifyResponse"]> {
  const result = await api.POST("/v1/sources/{source_id}/ownership/verify", {
    params: { path: { source_id: sourceId } },
    body: { challenge_id: challengeId, proof },
  });
  return throwIfApiError(result);
}
