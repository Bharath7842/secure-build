import type { AstStackSummary, AstSummary } from "@/lib/types";

/** Generic node for rendering `AstSummary` as an expandable tree, mirroring
 * the shape `ProjectStructurePanel` renders as flat ASCII lines but keeping
 * this data's real hierarchy (stack -> group -> annotation/entry-point). */
export interface AstTreeNode {
  id: string;
  label: string;
  /** Short count/status chip shown to the right of the label. */
  badge?: string;
  tone?: "default" | "warning";
  /** Secondary line (e.g. file path), rendered smaller/mono under the label. */
  meta?: string;
  children?: AstTreeNode[];
}

const STACK_LABELS: Record<string, string> = {
  "maven-java": "Java (Spring)",
  angular: "Angular",
};

const STACK_LANG_KEY: Record<string, string> = {
  "maven-java": "java",
  angular: "typescript",
};

function pluralize(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

function annotationChildren(annotations: Record<string, number> | undefined): AstTreeNode[] {
  if (!annotations) return [];
  return Object.entries(annotations)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([name, count]) => ({
      id: `annotation-${name}`,
      label: name,
      badge: String(count),
    }));
}

function entryPointChildren(stack: AstStackSummary): AstTreeNode[] {
  if (!stack.entry_points) return [];
  return stack.entry_points.map((ep, i) => ({
    id: `entry-${i}`,
    label: ep.verb ? `${ep.verb} ${ep.path}` : ep.path,
    badge: ep.authorized ? undefined : "unauthenticated",
    tone: ep.authorized ? "default" : "warning",
    meta: `${ep.class}.${ep.method} · ${ep.file}`,
  }));
}

function routeChildren(stack: AstStackSummary): AstTreeNode[] {
  if (!stack.routes) return [];
  return stack.routes.map((route, i) => ({
    id: `route-${i}`,
    label: `/${route.path}`.replace(/^\/+/, "/"),
    badge: route.guarded ? undefined : "unguarded",
    tone: route.guarded ? "default" : "warning",
    meta: route.file,
  }));
}

function stackGroups(stackKey: string, stack: AstStackSummary): AstTreeNode[] {
  const groups: AstTreeNode[] = [];

  if (stack.annotations && Object.keys(stack.annotations).length > 0) {
    const children = annotationChildren(stack.annotations);
    groups.push({
      id: `${stackKey}-annotations`,
      label: "Annotations",
      badge: pluralize(children.length, "type"),
      children,
    });
  }

  if (stack.decorators && Object.keys(stack.decorators).length > 0) {
    const children = annotationChildren(stack.decorators);
    groups.push({
      id: `${stackKey}-decorators`,
      label: "Decorators",
      badge: pluralize(children.length, "type"),
      children,
    });
  }

  if (stack.entry_points) {
    const unauth = stack.unauthenticated_entry_points ?? 0;
    groups.push({
      id: `${stackKey}-entry-points`,
      label: "Entry points",
      badge:
        unauth > 0
          ? `${stack.entry_point_count ?? stack.entry_points.length} · ${unauth} unauthenticated`
          : String(stack.entry_point_count ?? stack.entry_points.length),
      tone: unauth > 0 ? "warning" : "default",
      children: entryPointChildren(stack),
    });
  }

  if (stack.routes) {
    const unguarded = stack.unguarded_route_count ?? 0;
    groups.push({
      id: `${stackKey}-routes`,
      label: "Routes",
      badge:
        unguarded > 0
          ? `${stack.route_count ?? stack.routes.length} · ${unguarded} unguarded`
          : String(stack.route_count ?? stack.routes.length),
      tone: unguarded > 0 ? "warning" : "default",
      children: routeChildren(stack),
    });
  }

  return groups;
}

/** Converts the persisted `ast_summary` dict into a tree for `AstSummaryPanel`. */
export function buildAstTree(summary: AstSummary): AstTreeNode[] {
  return Object.entries(summary.stacks || {}).map(([stackKey, stack]) => {
    const langKey = STACK_LANG_KEY[stackKey] ?? stackKey;
    const parsed = summary.parsed_files?.[langKey];
    const capped = summary.capped?.[langKey];
    const badgeParts: string[] = [];
    if (typeof parsed === "number") badgeParts.push(pluralize(parsed, "file"));
    if (capped) badgeParts.push("capped");

    return {
      id: stackKey,
      label: STACK_LABELS[stackKey] ?? stackKey,
      badge: badgeParts.length > 0 ? badgeParts.join(" · ") : undefined,
      children: stackGroups(stackKey, stack),
    };
  });
}

/** Flattens the tree for search — returns every node whose label/meta matches
 * plus its ancestors, so a match stays visible with enough context. */
export function filterAstTree(nodes: AstTreeNode[], query: string): AstTreeNode[] {
  const q = query.trim().toLowerCase();
  if (!q) return nodes;

  function filterNode(node: AstTreeNode): AstTreeNode | null {
    const selfMatch =
      node.label.toLowerCase().includes(q) || (node.meta?.toLowerCase().includes(q) ?? false);
    const filteredChildren = (node.children ?? [])
      .map(filterNode)
      .filter((n): n is AstTreeNode => n !== null);

    if (!selfMatch && filteredChildren.length === 0) return null;
    if (!node.children) return selfMatch ? node : null;
    return { ...node, children: filteredChildren };
  }

  return nodes.map(filterNode).filter((n): n is AstTreeNode => n !== null);
}

/** Total leaf-node count across the tree, used for the panel subtitle. */
export function countAstLeaves(nodes: AstTreeNode[]): number {
  let total = 0;
  for (const node of nodes) {
    if (!node.children || node.children.length === 0) {
      total += 1;
    } else {
      total += countAstLeaves(node.children);
    }
  }
  return total;
}
