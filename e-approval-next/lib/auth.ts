"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api-client";

/** USER 일반 사용자 · ADMIN 관리자 · SUPER_ADMIN 대표(최고 관리자) */
export type Role = "USER" | "ADMIN" | "SUPER_ADMIN";

export const ROLE_LABEL: Record<Role, string> = {
  USER: "일반 사용자",
  ADMIN: "관리자",
  SUPER_ADMIN: "최고 관리자(대표)",
};

export function canManageUsers(user: Pick<User, "role"> | null | undefined): boolean {
  return user?.role === "ADMIN" || user?.role === "SUPER_ADMIN";
}

export type User = {
  id: number;
  loginId: string;
  name: string;
  department: string;
  position: string | null;
  positionLabel: string;
  role: Role;
  status: "PENDING" | "ACTIVE" | "REJECTED";
  createdAt: string;
};

export type SignupFormData = {
  loginId: string;
  password: string;
  name: string;
  department: string;
  position: string;
};

const EVENT = "auth-change";
const CACHE_KEY = "approval-user";

function readCachedUser(): User | null {
  try {
    const value = localStorage.getItem(CACHE_KEY);
    return value ? (JSON.parse(value) as User) : null;
  } catch {
    return null;
  }
}

function writeCachedUser(user: User | null) {
  try {
    if (user) localStorage.setItem(CACHE_KEY, JSON.stringify(user));
    else localStorage.removeItem(CACHE_KEY);
  } catch {
    // 시크릿 모드 등 저장소를 쓸 수 없는 환경은 무시
  }
}

function notifyAuthChanged() {
  if (typeof window !== "undefined") window.dispatchEvent(new Event(EVENT));
}

let pendingMe: Promise<User | null> | null = null;

function fetchCurrentUser(): Promise<User | null> {
  if (!pendingMe) {
    pendingMe = api<User>("/api/auth/me")
      .then((user) => {
        writeCachedUser(user);
        return user;
      })
      .catch(() => {
        writeCachedUser(null);
        return null;
      })
      .finally(() => {
        pendingMe = null;
      });
  }
  return pendingMe;
}

export const apiRequest = api;

export async function login(loginId: string, password: string): Promise<User> {
  const user = await api<User>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ loginId, password }),
  });
  writeCachedUser(user);
  notifyAuthChanged();
  return user;
}

export async function signup(form: SignupFormData): Promise<{ message: string; user: User }> {
  return api("/api/auth/signup", {
    method: "POST",
    body: JSON.stringify(form),
  });
}

export async function logout(): Promise<void> {
  try {
    await api<void>("/api/auth/logout", { method: "POST" });
  } catch {
    // 서버가 꺼져 있어도 화면에서는 로그아웃 처리
  } finally {
    writeCachedUser(null);
    if (typeof window !== "undefined") window.dispatchEvent(new Event("approval-logout"));
    notifyAuthChanged();
  }
}

export function useAuthState() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;

    const sync = () => {
      setLoading(true);
      fetchCurrentUser().then((u) => {
        if (!active) return;
        setUser(u);
        setLoading(false);
      });
    };

    const onStorage = (e: StorageEvent) => {
      if (e.key === CACHE_KEY && active) setUser(readCachedUser());
    };

    window.addEventListener(EVENT, sync);
    window.addEventListener("storage", onStorage);
    sync();

    return () => {
      active = false;
      window.removeEventListener(EVENT, sync);
      window.removeEventListener("storage", onStorage);
    };
  }, []);

  return { user, isLoggedIn: Boolean(user), loading };
}

export function safeNextPath(value: string | null | undefined): string {
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\")) return "/";
  return value;
}
