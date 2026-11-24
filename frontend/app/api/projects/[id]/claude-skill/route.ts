import { NextRequest, NextResponse } from "next/server";

import { sastFetch } from "@/lib/server-sast";

type RouteParams = { params: Promise<{ id: string }> };

// The generated `secure-fix` SKILL.md for this project (project id and API address filled in, no token).
export async function GET(_request: NextRequest, { params }: RouteParams) {
  const { id } = await params;
  try {
    const res = await sastFetch(`/projects/${id}/claude-skill`);
    if (!res.ok) {
      const body = await res.json().catch(() => ({ detail: "Could not build the skill file" }));
      return NextResponse.json(body, { status: res.status });
    }
    return new NextResponse(await res.text(), {
      status: 200,
      headers: {
        "Content-Type": "text/markdown; charset=utf-8",
        "Content-Disposition": res.headers.get("content-disposition") || 'attachment; filename="SKILL.md"',
        "Cache-Control": "no-store",
      },
    });
  } catch (err) {
    return NextResponse.json(
      { detail: err instanceof Error ? err.message : "Failed to reach SAST API" },
      { status: 500 }
    );
  }
}
