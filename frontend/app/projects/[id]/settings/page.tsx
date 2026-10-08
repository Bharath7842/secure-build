"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";

import DastRuleManager from "@/components/DastRuleManager";
import PageContainer from "@/components/PageContainer";
import ScanLimitationsPanel from "@/components/ScanLimitationsPanel";
import { ApiError, api } from "@/lib/api";
import type { Project, ScanLimitation } from "@/lib/types";

export default function ProjectSettingsPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;

  const [project, setProject] = useState<Project | null>(null);
  const [limitations, setLimitations] = useState<ScanLimitation[]>([]);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const proj = await api.projects.get(id);
        const lims = await api.config.scanLimitations();

        if (active) {
          setProject(proj);
          setLimitations(lims);

          // Initialize selected IDs from project config or all enabled by default
          const enabled = new Set<string>();
          for (const lim of lims) {
            const isEnabled =
              proj.limitations_config?.[lim.id] ?? lim.enabled_by_default;
            if (isEnabled) {
              enabled.add(lim.id);
            }
          }
          setSelectedIds(enabled);
        }
      } catch (err) {
        if (active) {
          setError(err instanceof ApiError ? err.message : "Failed to load settings.");
        }
      } finally {
        if (active) setLoading(false);
      }
    }

    load();
    return () => {
      active = false;
    };
  }, [id]);

  const handleSave = async () => {
    if (!project) return;
    setSaving(true);
    setError(null);
    setSaveMessage(null);

    try {
      const updated = await api.projects.updateLimitations(project.id, Array.from(selectedIds));
      setProject(updated);
      setSaveMessage("Settings saved successfully.");
      setTimeout(() => setSaveMessage(null), 3000);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to save settings.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <PageContainer>
      <div className="mb-6">
        <Link
          href={`/projects/${id}`}
          className="text-sm text-blue-600 dark:text-blue-400 hover:underline"
        >
          ← Back to project
        </Link>
      </div>

      {loading && <div className="text-center py-12 text-gray-500">Loading settings...</div>}

      {error && (
        <div className="bg-red-50 dark:bg-red-900/10 border border-red-200 dark:border-red-800 rounded-lg p-4 text-red-800 dark:text-red-200 mb-6">
          {error}
        </div>
      )}

      {saveMessage && (
        <div className="bg-green-50 dark:bg-green-900/10 border border-green-200 dark:border-green-800 rounded-lg p-4 text-green-800 dark:text-green-200 mb-6">
          {saveMessage}
        </div>
      )}

      {!loading && project && limitations.length > 0 && (
        <>
          <div className="mb-8">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
              {project.name}
            </h1>
            <p className="text-gray-600 dark:text-gray-400">Scan Configuration</p>
          </div>

          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6 mb-6">
            <ScanLimitationsPanel
              limitations={limitations}
              selectedIds={selectedIds}
              onChange={setSelectedIds}
              disabled={saving}
            />
          </div>

          <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6 mb-6">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-1">DAST rules</h2>
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
              Overrides for this project&apos;s DAST scans, on top of the{" "}
              <Link href="/dast/settings" className="text-blue-600 hover:underline">global rule settings</Link>. These save as you change them.
            </p>
            <DastRuleManager projectId={project.id} />
          </div>

          <div className="flex gap-3">
            <button
              onClick={handleSave}
              disabled={saving}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-lg font-medium"
            >
              {saving ? "Saving..." : "Save Settings"}
            </button>
            <Link
              href={`/projects/${id}`}
              className="px-4 py-2 bg-gray-200 dark:bg-gray-800 hover:bg-gray-300 dark:hover:bg-gray-700 text-gray-900 dark:text-white rounded-lg font-medium"
            >
              Cancel
            </Link>
          </div>
        </>
      )}
    </PageContainer>
  );
}
