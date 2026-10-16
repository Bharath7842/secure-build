@AGENTS.md

## Creating new pages

Whenever you create a new page or route (`app/**/page.tsx`, `layout.tsx`) or a new top-level UI component, invoke the `ui-ux-pro-max` skill (`.claude/skills/ui-ux-pro-max/`, source: https://github.com/nextlevelbuilder/ui-ux-pro-max-skill) via the Skill tool before writing UI code. Run its searches from the repo root (`--stack nextjs`, `--domain ux`).

- Match the existing UI first: Tailwind v4 plus the CSS-variable tokens in `app/globals.css` (`--canvas`, `--ink`, `--accent`, ...) and the hand-written components in `components/`. Use the skill's recommendations to fill gaps; do not introduce a new palette, font or component library from it.
- Do not run it with `--persist` or `--force` (it writes `design-system/` files) without asking the user.
