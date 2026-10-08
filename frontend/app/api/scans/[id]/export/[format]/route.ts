import { NextRequest, NextResponse } from "next/server";

import { proxyFailure } from "@/lib/server-dast";
import { sastFetch } from "@/lib/server-sast";

const ALLOWED = new Set(["pdf", "xlsx"]);

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string; format: string }> }
) {
  const { id, format } = await params;
  if (!ALLOWED.has(format)) {
    return NextResponse.json({ detail: "Unsupported export format" }, { status: 400 });
  }

  try {
    const res = await sastFetch(`/scans/${id}/export.${format}`);
    if (!res.ok) {
      const body = await res.json().catch(() => ({ detail: "Export failed" }));
      return NextResponse.json(body, { status: res.status });
    }

    const bytes = await res.arrayBuffer();
    const contentType =
      res.headers.get("content-type") ||
      (format === "pdf"
        ? "application/pdf"
        : "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    const disposition =
      res.headers.get("content-disposition") ||
      `attachment; filename="scan-export.${format}"`;

    return new NextResponse(bytes, {
      status: 200,
      headers: {
        "Content-Type": contentType,
        "Content-Disposition": disposition,
        "Cache-Control": "no-store",
      },
    });
  } catch (err) {
    return proxyFailure(err);
  }
}
