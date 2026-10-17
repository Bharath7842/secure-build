"use client";

import { createContext, useContext } from "react";
import type { ReactNode } from "react";

import type { Me } from "@/lib/access";

const AuthContext = createContext<Me | null>(null);

/** Makes the signed-in user (from the root layout's server-side check)
 *  available to client components. Holds no token: the session cookie is
 *  HttpOnly and never reaches client code. */
export function AuthProvider({ me, children }: { me: Me | null; children: ReactNode }) {
  return <AuthContext.Provider value={me}>{children}</AuthContext.Provider>;
}

/** The signed-in user, or null on public pages. */
export function useAuth(): Me | null {
  return useContext(AuthContext);
}

/** Whether to show UI for an action or page key. For display only: the
 *  backend checks every request itself. */
export function useCan(): (key: string) => boolean {
  const me = useContext(AuthContext);
  return (key: string) => !!me && (me.permissions.includes(key) || me.pages.includes(key));
}
