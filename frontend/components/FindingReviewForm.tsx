"use client";

import { useEffect, useState } from "react";

import { useAuth } from "@/components/auth/AuthProvider";
import { ApiError, api } from "@/lib/api";
import { inputClass, selectClass } from "@/lib/formStyles";
import {
  DECISION_LABEL,
  ISSUE_STATUS_CHIP,
  ISSUE_STATUS_LABEL,
  LEARNING_CHIP,
  LEARNING_LABEL,
  OVERRIDE_CHIP,
  describeEvent,
  formatWhen,
  llmVerdictLabel,
} from "@/lib/review";
import type { FeedbackRow, ReviewDecision } from "@/lib/types";

interface Props {
  scanId: string;
  findingId: string;
  /** The engine's own verdict, which decides whether agreeing with it needs a reason. */
  llmVerdict: string | null | undefined;
  /** Whether a review already exists (so its history is worth fetching). */
  hasReview: boolean;
  /** The row's construct has members with different outcomes: say which members a decision covers. */
  constructMixed?: boolean;
  /** How many occurrences this row stands for. */
  occurrenceCount?: number;
  /** Called with the saved review so the parent can refresh its view. */
  onSaved?: (row: FeedbackRow) => void;
}

const ALL_DECISIONS: ReviewDecision[] = [
  "confirmed_issue",
  "false_positive",
  "needs_more_info",
  "resolved",
  "accept_risk",
];

export default function FindingReviewForm({
  scanId,
  findingId,
  llmVerdict,
  hasReview,
  constructMixed = false,
  occurrenceCount = 1,
  onSaved,
}: Props) {
  const [review, setReview] = useState<FeedbackRow | null>(null);
  // For a mixed construct the server will not guess: "this occurrence only" or "all N in this row".
  const [scope, setScope] = useState<"one" | "all">("one");
  const [decision, setDecision] = useState<ReviewDecision>("confirmed_issue");
  const [comment, setComment] = useState("");
  const me = useAuth();
  // Display only: the backend refuses a review without findings.review.
  const canReview = !!me?.permissions.includes("findings.review");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!hasReview) return;
    let active = true;
    api.feedback
      .forFinding(scanId, findingId)
      .then((row) => active && setReview(row))
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, [scanId, findingId, hasReview]);

  const confirmed = review?.reviewer_verdict === "confirmed_issue";
  const isClosingDecision = decision === "resolved" || decision === "accept_risk";
  const agreesWithLlm = decision === "confirmed_issue" && llmVerdict === "true_positive";
  const reasonRequired = !agreesWithLlm;
  const overrides =
    (decision === "false_positive" && llmVerdict === "true_positive") ||
    (decision === "confirmed_issue" && llmVerdict === "false_positive");

  const reasonLabel =
    decision === "resolved"
      ? "Resolution notes"
      : decision === "accept_risk"
        ? "Why the risk is acceptable"
        : overrides
          ? "Reason for overriding the LLM verdict"
          : "Reason";

  const canSubmit =
    !busy && (!reasonRequired || comment.trim() !== "") && (!isClosingDecision || confirmed);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      // Only a first review of a mixed construct needs a scope; later decisions update that review.
      const scoped =
        constructMixed && !review
          ? scope === "all" && occurrenceCount > 1
            ? { apply_to: "all" as const }
            : { member_ids: [findingId] }
          : {};
      const saved = await api.feedback.submit(scanId, findingId, {
        decision,
        ...(isClosingDecision ? { resolution_notes: comment.trim() } : { comment: comment.trim() }),
        ...scoped,
      });
      setReview(saved);
      setComment("");
      onSaved?.(saved);
    } catch (err) {
      setError(err instanceof ApiError || err instanceof Error ? err.message : "Could not save the review.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mt-3 rounded-md border border-slate-200 bg-white p-3 text-xs" data-testid="finding-review">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-semibold text-[var(--ink)]">Reviewer feedback</span>
        {review ? (
          <>
            <span className={ISSUE_STATUS_CHIP[review.issue_status]}>{ISSUE_STATUS_LABEL[review.issue_status]}</span>
            {review.is_override ? <span className={OVERRIDE_CHIP}>Verdict override</span> : null}
            {review.learning_status ? (
              <span className={LEARNING_CHIP[review.learning_status]}>{LEARNING_LABEL[review.learning_status]}</span>
            ) : null}
          </>
        ) : (
          <span className="text-[var(--muted)]">Not reviewed yet — this finding is still open.</span>
        )}
      </div>

      {review ? (
        <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
          <dt className="text-[var(--muted)]">LLM verdict</dt>
          <dd>{llmVerdictLabel(review.llm_verdict)}</dd>
          <dt className="text-[var(--muted)]">Reviewer verdict</dt>
          <dd>{review.reviewer_verdict ? DECISION_LABEL[review.reviewer_verdict] : "—"}</dd>
          {review.reviewer_comment ? (
            <>
              <dt className="text-[var(--muted)]">Reason</dt>
              <dd className="whitespace-pre-wrap">{review.reviewer_comment}</dd>
            </>
          ) : null}
          {review.resolution_notes ? (
            <>
              <dt className="text-[var(--muted)]">Resolution</dt>
              <dd className="whitespace-pre-wrap">
                {review.resolution_notes} — {review.resolved_by}, {formatWhen(review.resolved_at)}
              </dd>
            </>
          ) : null}
          <dt className="text-[var(--muted)]">Reviewed</dt>
          <dd>
            {review.reviewer}, {formatWhen(review.reviewed_at)}
          </dd>
        </dl>
      ) : null}

      {canReview && (
        <>
        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          <label className="block">
            <span className="text-[var(--muted)]">Decision</span>
            <select
              className={`${selectClass} !py-1.5 !text-xs`}
              value={decision}
              onChange={(e) => setDecision(e.target.value as ReviewDecision)}
            >
              {ALL_DECISIONS.map((value) => (
                <option key={value} value={value} disabled={(value === "resolved" || value === "accept_risk") && !confirmed}>
                  {DECISION_LABEL[value]}
                  {(value === "resolved" || value === "accept_risk") && !confirmed ? " (confirm the issue first)" : ""}
                </option>
              ))}
            </select>
          </label>
          <div className="block">
            <span className="text-[var(--muted)]">Recorded as</span>
            <p className="mt-1.5 truncate py-1.5 text-[var(--ink)]" title={me?.user.email}>
              {me?.user.display_name || me?.user.email}
            </p>
          </div>
        </div>
        {constructMixed && !review ? (
          <fieldset className="mt-2 rounded border border-amber-200 bg-amber-50/60 px-2.5 py-2" data-testid="review-scope">
            <legend className="px-1 text-amber-900">
              This construct has members with different outcomes. Which does your decision cover?
            </legend>
            <label className="mr-4 inline-flex items-center gap-1.5">
              <input type="radio" name={`scope-${findingId}`} checked={scope === "one"} onChange={() => setScope("one")} />
              This occurrence only
            </label>
            {occurrenceCount > 1 ? (
              <label className="inline-flex items-center gap-1.5">
                <input type="radio" name={`scope-${findingId}`} checked={scope === "all"} onChange={() => setScope("all")} />
                All {occurrenceCount} in this row
              </label>
            ) : null}
          </fieldset>
        ) : null}
        <label className="mt-2 block">
          <span className="text-[var(--muted)]">
            {reasonLabel}
            {reasonRequired ? " (required)" : " (optional)"}
          </span>
          <textarea
            className={`${inputClass} !text-xs`}
            rows={2}
            value={comment}
            onChange={(e) => setComment(e.target.value)}
          />
        </label>
        {overrides ? (
          <p className="mt-1 text-violet-700">This overrides the LLM verdict; both are kept.</p>
        ) : null}
        {error ? (
          <p role="alert" className="mt-2 text-red-700">
            {error}
          </p>
        ) : null}
        <div className="mt-2 flex items-center gap-2">
          <button
            type="button"
            onClick={submit}
            disabled={!canSubmit}
            className="rounded-md bg-[var(--accent)] px-3 py-1.5 text-xs font-medium text-white disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? "Saving…" : "Save decision"}
          </button>
        </div>
        </>
      )}

      {review && review.events.length > 0 ? (
        <details className="mt-3">
          <summary className="cursor-pointer text-[var(--muted)]">History ({review.events.length})</summary>
          <ol className="mt-1.5 space-y-1.5 border-l border-slate-200 pl-3">
            {[...review.events].reverse().map((event) => (
              <li key={event.id}>
                <div>{describeEvent(event)}</div>
                {event.comment ? <div className="whitespace-pre-wrap text-[var(--muted)]">“{event.comment}”</div> : null}
                <div className="text-[var(--muted)]">{formatWhen(event.at)}</div>
              </li>
            ))}
          </ol>
        </details>
      ) : null}
    </div>
  );
}
