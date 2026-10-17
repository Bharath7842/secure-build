import type {
  AppRole,
  AppUser,
  AuditEvent,
  OneTimeLink,
  Override,
  Page,
  PermissionEntry,
  SessionInfo,
  UserAccess,
  UserDetail,
} from "@/lib/access";
import type {
  DastAuthzMatrix,
  DastCatalog,
  DastCustomRule,
  DastCustomRuleValidation,
  DastDiff,
  DastEffectivePreview,
  DastFindingFilter,
  DastModelRoute,
  DastModelRouteTestResult,
  DastProviders,
  DastReport,
  DastRequestAuditPage,
  DastRuleConfigPatch,
  DastRuleSettings,
  DastSettings,
  DastSettingsUpdate,
  DastSummary,
  DastVulnerabilityCoverage,
  FeedbackFilter,
  FeedbackList,
  FeedbackRow,
  GitRepo,
  ModelCatalog,
  Project,
  ProjectCreateInput,
  ProjectDeleteResult,
  ProjectUpdateInput,
  ReviewInput,
  Scan,
  ScanCreateInput,
  ScanFindings,
  ScanLimitation,
  DastNarration,
  ScanLogs,
  ScanResults,
  ScanStatus,
  ScanTrigger,
} from "@/lib/types";

/** A readable message from a FastAPI error body: a plain string, a list of validation problems, or
 *  `{errors: [{field, message}]}` (the settings and rule endpoints). */
function detailMessage(body: unknown, status: number): string {
  const fallback = `Request failed with status ${status}`;
  if (typeof body !== "object" || body === null || !("detail" in body)) return fallback;
  const detail = (body as { detail: unknown }).detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        if (item && typeof item === "object" && "msg" in item) {
          const loc = Array.isArray((item as { loc?: unknown[] }).loc) ? (item as { loc: unknown[] }).loc.filter((p) => p !== "body").join(".") : "";
          return `${loc ? `${loc}: ` : ""}${String((item as { msg: unknown }).msg)}`;
        }
        return String(item);
      })
      .join("; ");
  }
  if (detail && typeof detail === "object" && "errors" in detail && Array.isArray((detail as { errors: unknown[] }).errors)) {
    return (detail as { errors: unknown[] }).errors
      .map((e) => {
        if (e && typeof e === "object" && "message" in e) {
          const item = e as { field?: string; message: string };
          return `${item.field ? `${item.field}: ` : ""}${item.message}`;
        }
        return String(e);
      })
      .join("; ");
  }
  return fallback;
}

class ApiError extends Error {
  status: number;
  body: unknown;

  constructor(status: number, body: unknown) {
    super(detailMessage(body, status));
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

/** Where to sign in again when the session has ended, coming back here after. */
export function signInAgainUrl(): string {
  const here = `${window.location.pathname}${window.location.search}`;
  return `/login?${new URLSearchParams({ next: here, reason: "expired" }).toString()}`;
}

/**
 * fetch for this app's /api routes. A 401 means the session expired or was
 * revoked (signed out elsewhere, password changed, account disabled): go to
 * sign-in rather than show a broken page. 403 is left to the caller.
 */
export async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const res = await fetch(path, init);
  if (res.status === 401 && typeof window !== "undefined") {
    window.location.assign(signInAgainUrl());
  }
  return res;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await apiFetch(path, {
    ...init,
    cache: "no-store",
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers || {}),
    },
  });

  const body = await res.json().catch(() => undefined);
  if (!res.ok) {
    throw new ApiError(res.status, body);
  }
  return body as T;
}

export const api = {
  /** The signed-in user's own account. */
  account: {
    changePassword: (currentPassword: string, newPassword: string): Promise<{ ok: true }> =>
      request("/api/auth/password", {
        method: "POST",
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
      }),
    sessions: (): Promise<SessionInfo[]> => request("/api/auth/sessions"),
    revokeOtherSessions: (): Promise<{ revoked: number }> =>
      request("/api/auth/sessions/revoke-others", { method: "POST" }),
  },
  /** User management and the audit log (admins). */
  admin: {
    catalog: (): Promise<{ permissions: PermissionEntry[]; roles: AppRole[] }> =>
      request("/api/admin/permissions/catalog"),
    users: (filter: { q?: string; role?: string; status?: string; cursor?: number } = {}): Promise<Page<AppUser>> => {
      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(filter)) {
        if (value !== undefined && value !== "") params.set(key, String(value));
      }
      const search = params.toString();
      return request(`/api/admin/users${search ? `?${search}` : ""}`);
    },
    createUser: (input: {
      email: string;
      display_name: string;
      role: AppRole;
      overrides?: Record<string, Override>;
    }): Promise<UserAccess & { user: AppUser; invite_url: string; invite_expires_at: string; added_dependencies: string[] }> =>
      request("/api/admin/users", { method: "POST", body: JSON.stringify(input) }),
    user: (id: string): Promise<UserDetail> => request(`/api/admin/users/${encodeURIComponent(id)}`),
    updateUser: (
      id: string,
      patch: { display_name?: string; role?: AppRole; is_active?: boolean },
    ): Promise<UserAccess & { user: AppUser }> =>
      request(`/api/admin/users/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(patch) }),
    setPermissions: (
      id: string,
      overrides: Record<string, Override>,
    ): Promise<UserAccess & { added_dependencies: string[] }> =>
      request(`/api/admin/users/${encodeURIComponent(id)}/permissions`, {
        method: "PUT",
        body: JSON.stringify({ overrides }),
      }),
    inviteLink: (id: string): Promise<OneTimeLink> =>
      request(`/api/admin/users/${encodeURIComponent(id)}/invite-link`, { method: "POST" }),
    resetLink: (id: string): Promise<OneTimeLink> =>
      request(`/api/admin/users/${encodeURIComponent(id)}/reset-link`, { method: "POST" }),
    audit: (filter: Record<string, string | number | undefined> = {}): Promise<Page<AuditEvent>> => {
      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(filter)) {
        if (value !== undefined && value !== "") params.set(key, String(value));
      }
      const search = params.toString();
      return request(`/api/admin/audit${search ? `?${search}` : ""}`);
    },
  },
  projects: {
    list: (): Promise<Project[]> => request("/api/projects"),
    create: (input: ProjectCreateInput): Promise<Project> =>
      request("/api/projects", { method: "POST", body: JSON.stringify(input) }),
    get: (id: string): Promise<Project> => request(`/api/projects/${id}`),
    update: (id: string, input: ProjectUpdateInput): Promise<Project> =>
      request(`/api/projects/${id}`, { method: "PATCH", body: JSON.stringify(input) }),
    updateLimitations: (id: string, enabledIds: string[]): Promise<Project> =>
      request(`/api/projects/${id}/limitations`, {
        method: "PATCH",
        body: JSON.stringify({ enabled_ids: enabledIds }),
      }),
    delete: (id: string): Promise<ProjectDeleteResult> =>
      request(`/api/projects/${id}`, { method: "DELETE" }),
  },
  gitAuth: {
    // `projectId` omitted when connecting from the new-project form, before
    // the project row exists — the resulting token is held in a short-lived
    // pending connection instead (see callback()).
    authorizeUrl: (
      provider: "gitlab",
      projectId?: string
    ): Promise<{ authorize_url: string }> => {
      const query = projectId ? `?project_id=${encodeURIComponent(projectId)}` : "";
      return request(`/api/git-auth/${provider}/authorize${query}`);
    },
    callback: (
      provider: "gitlab",
      code: string,
      state: string
    ): Promise<{ git_provider: string; project_id?: string; connection_id?: string }> =>
      request(`/api/git-auth/${provider}/callback`, {
        method: "POST",
        body: JSON.stringify({ code, state }),
      }),
    disconnect: (projectId: string): Promise<void> =>
      request(`/api/git-auth/disconnect/${projectId}`, { method: "DELETE" }),
    lookupRepo: (
      provider: "gitlab",
      url: string,
      by: { connectionId?: string; projectId?: string }
    ): Promise<GitRepo> => {
      const query = new URLSearchParams({ url });
      if (by.connectionId) query.set("connection_id", by.connectionId);
      if (by.projectId) query.set("project_id", by.projectId);
      return request(`/api/git-auth/${provider}/repo?${query.toString()}`);
    },
  },
  scans: {
    list: (projectId?: string, scanType?: "sast" | "sca" | "sbom" | "dast"): Promise<Scan[]> => {
      const params = new URLSearchParams();
      if (projectId) params.set("project_id", projectId);
      if (scanType) params.set("scan_type", scanType);
      const search = params.toString();
      return request(`/api/scans${search ? `?${search}` : ""}`);
    },
    create: (input: ScanCreateInput): Promise<ScanTrigger> =>
      request("/api/scans", { method: "POST", body: JSON.stringify(input) }),
    status: (id: string): Promise<ScanStatus> => request(`/api/scans/${id}/status`),
    results: (id: string): Promise<ScanResults> => request(`/api/scans/${id}/results`),
    findings: (
      id: string,
      verdict?: "true_positive" | "false_positive" | "unverified",
    ): Promise<ScanFindings> => {
      const search = verdict ? `?verdict=${encodeURIComponent(verdict)}` : "";
      return request(`/api/scans/${id}/findings${search}`);
    },
    logs: (id: string, after = 0): Promise<ScanLogs> =>
      request(`/api/scans/${id}/logs?after=${after}`),
    narration: (id: string): Promise<DastNarration> => request(`/api/scans/${id}/narration`),
    narrationStream: async (id: string, step: string): Promise<ReadableStreamDefaultReader> => {
      const res = await apiFetch(`/api/scans/${id}/narration/stream?step=${encodeURIComponent(step)}`);
      if (!res.ok) throw new Error(`${res.status}`);
      return res.body!.getReader();
    },
    /** DAST findings with the full filter set (severity, verdict, role pair, check). */
    dastFindings: (id: string, filter: DastFindingFilter = {}): Promise<ScanFindings> => {
      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(filter)) {
        if (value) params.set(key, String(value));
      }
      const search = params.toString();
      return request(`/api/scans/${id}/findings${search ? `?${search}` : ""}`);
    },
    authzMatrix: (id: string): Promise<DastAuthzMatrix> => request(`/api/scans/${id}/authz-matrix`),
    diff: (id: string, against?: string): Promise<DastDiff> =>
      request(`/api/scans/${id}/diff${against ? `?against=${encodeURIComponent(against)}` : ""}`),
    /** Live counters (pages, endpoints, requests, tests, findings by severity); cheap to poll. */
    summary: (id: string): Promise<DastSummary> => request(`/api/scans/${id}/summary`),
    /** The report data set: severity totals, unverified apart, evidence, skipped checks, the diff. */
    report: (id: string, against?: string): Promise<DastReport> =>
      request(`/api/scans/${id}/report${against ? `?against=${encodeURIComponent(against)}` : ""}`),
    requests: (
      id: string,
      after = 0,
      opts: { allowed?: boolean; limit?: number } = {},
    ): Promise<DastRequestAuditPage> => {
      const params = new URLSearchParams({ after: String(after) });
      if (opts.allowed !== undefined) params.set("allowed", String(opts.allowed));
      if (opts.limit !== undefined) params.set("limit", String(opts.limit));
      return request(`/api/scans/${id}/requests?${params.toString()}`);
    },
    delete: async (id: string): Promise<void> => {
      const res = await apiFetch(`/api/scans/${id}`, { method: "DELETE" });
      if (!res.ok) {
        const body = await res.json().catch(() => undefined);
        throw new ApiError(res.status, body);
      }
    },
    cancel: (id: string): Promise<ScanStatus> =>
      request(`/api/scans/${id}/cancel`, { method: "POST" }),
  },
  feedback: {
    list: (filter: FeedbackFilter = {}): Promise<FeedbackList> => {
      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(filter)) {
        if (value !== undefined && value !== "") params.set(key, String(value));
      }
      const search = params.toString();
      return request(`/api/feedback${search ? `?${search}` : ""}`);
    },
    get: (reviewId: string): Promise<FeedbackRow> => request(`/api/feedback/${reviewId}`),
    /** The review (with history) for the issue group a finding belongs to; rejects with 404 if none. */
    forFinding: (scanId: string, findingId: string): Promise<FeedbackRow> =>
      request(`/api/scans/${scanId}/findings/${findingId}/review`),
    submit: (scanId: string, findingId: string, input: ReviewInput): Promise<FeedbackRow> =>
      request(`/api/scans/${scanId}/findings/${findingId}/review`, {
        method: "POST",
        body: JSON.stringify(input),
      }),
    // The signed-in user is recorded as the actor.
    approveForLearning: (reviewIds: string[]): Promise<{ updated: number; skipped: number }> =>
      request("/api/feedback/learning/approve", {
        method: "POST",
        body: JSON.stringify({ review_ids: reviewIds }),
      }),
    markProcessed: (reviewIds: string[]): Promise<{ updated: number; skipped: number }> =>
      request("/api/feedback/learning/mark-processed", {
        method: "POST",
        body: JSON.stringify({ review_ids: reviewIds }),
      }),
  },
  config: {
    scanLimitations: (): Promise<ScanLimitation[]> =>
      request("/api/config/scan-limitations"),
  },
  /** App-wide settings. `models` controls which models the model selects offer (UI only). */
  settings: {
    models: {
      get: (): Promise<ModelCatalog> => request("/api/settings/models"),
      update: (hidden: string[]): Promise<ModelCatalog> =>
        request("/api/settings/models", { method: "PATCH", body: JSON.stringify({ hidden }) }),
    },
  },
  /** DAST settings, rule sets and model routing. Credentials are never accepted or returned. */
  dast: {
    settings: {
      get: (): Promise<DastSettings> => request("/api/dast/settings"),
      update: (input: DastSettingsUpdate): Promise<DastSettings> =>
        request("/api/dast/settings", { method: "PATCH", body: JSON.stringify(input) }),
    },
    modelRouting: {
      get: (): Promise<DastModelRoute[]> => request("/api/dast/model-routing"),
      update: (routes: Pick<DastModelRoute, "task" | "provider" | "model">[]): Promise<DastModelRoute[]> =>
        request("/api/dast/model-routing", { method: "PUT", body: JSON.stringify(routes) }),
      /** One harmless call for this task's provider and model; reports success or why not. */
      test: (route: Pick<DastModelRoute, "task" | "provider" | "model">): Promise<DastModelRouteTestResult> =>
        request("/api/dast/model-routing/test", { method: "POST", body: JSON.stringify(route) }),
    },
    /** Read-only "configured / not configured" per provider (keys live in the environment). */
    providers: (): Promise<DastProviders> => request("/api/dast/providers"),
    catalog: (): Promise<DastCatalog> => request("/api/dast/catalog"),
    vulnerabilityCoverage: (): Promise<DastVulnerabilityCoverage> => request("/api/dast/vulnerability-coverage"),
    ruleSettings: (projectId?: string): Promise<DastRuleSettings> =>
      request(`/api/dast/rule-settings${projectId ? `?project_id=${encodeURIComponent(projectId)}` : ""}`),
    rules: {
      updateGlobal: (patch: DastRuleConfigPatch): Promise<unknown> =>
        request("/api/dast/rules", { method: "PATCH", body: JSON.stringify(patch) }),
      updateProject: (projectId: string, patch: DastRuleConfigPatch): Promise<unknown> =>
        request(`/api/projects/${projectId}/dast-rules`, { method: "PATCH", body: JSON.stringify(patch) }),
      resetProject: async (projectId: string): Promise<void> => {
        const res = await apiFetch(`/api/projects/${projectId}/dast-rules`, { method: "DELETE" });
        if (!res.ok) {
          const body = await res.json().catch(() => undefined);
          throw new ApiError(res.status, body);
        }
      },
      /** What a scan would run with now. `packs` previews a per-scan pack selection. */
      effective: (opts: { projectId?: string; packs?: string[]; secondIdentity?: boolean; oast?: boolean } = {}): Promise<DastEffectivePreview> => {
        const params = new URLSearchParams();
        if (opts.projectId) params.set("project_id", opts.projectId);
        if (opts.packs) params.set("packs", opts.packs.join(","));
        if (opts.secondIdentity !== undefined) params.set("second_identity", String(opts.secondIdentity));
        if (opts.oast !== undefined) params.set("oast", String(opts.oast));
        const search = params.toString();
        return request(`/api/dast/rules/effective${search ? `?${search}` : ""}`);
      },
    },
    customRules: {
      list: async (): Promise<DastCustomRule[]> => (await request<{ rules: DastCustomRule[] }>("/api/dast/custom-rules")).rules,
      /** Validates without saving: every error with its field, plus notes (e.g. assist-only). */
      validate: (yaml: string): Promise<DastCustomRuleValidation> =>
        request("/api/dast/custom-rules/validate", { method: "POST", body: JSON.stringify({ yaml }) }),
      create: (yaml: string): Promise<DastCustomRule> =>
        request("/api/dast/custom-rules", { method: "POST", body: JSON.stringify({ yaml }) }),
      update: (checkId: string, yaml: string): Promise<DastCustomRule> =>
        request(`/api/dast/custom-rules/${encodeURIComponent(checkId)}`, { method: "PUT", body: JSON.stringify({ yaml }) }),
      delete: async (checkId: string): Promise<void> => {
        const res = await apiFetch(`/api/dast/custom-rules/${encodeURIComponent(checkId)}`, { method: "DELETE" });
        if (!res.ok) {
          const body = await res.json().catch(() => undefined);
          throw new ApiError(res.status, body);
        }
      },
    },
  },
};

export { ApiError };
