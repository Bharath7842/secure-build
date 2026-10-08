"use client";

import { useEffect, useState } from "react";

/** Matches Tailwind's `lg` breakpoint — the point where a side-by-side split has room to breathe. */
export const DESKTOP_SPLIT_QUERY = "(min-width: 1024px)";

export function useMediaQuery(query: string, defaultValue = true): boolean {
  const [matches, setMatches] = useState(defaultValue);

  useEffect(() => {
    const mql = window.matchMedia(query);
    setMatches(mql.matches);

    function handleChange(e: MediaQueryListEvent) {
      setMatches(e.matches);
    }

    mql.addEventListener("change", handleChange);
    return () => mql.removeEventListener("change", handleChange);
  }, [query]);

  return matches;
}
