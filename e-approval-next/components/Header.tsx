"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { canManageUsers, logout, useAuthState } from "@/lib/auth";
import { useUnreadCount } from "@/features/messenger/useUnreadCount";
import { usePendingApprovalNotifications } from "@/features/approval/usePendingApprovalNotifications";

type Props = { variant?: "home" | "auth" | "default" };

export default function Header({ variant = "default" }: Props) {
  const router = useRouter();
  const { user, isLoggedIn, loading } = useAuthState();
  const enabled = variant !== "auth" && isLoggedIn;
  const unread = useUnreadCount(enabled);
  const approval = usePendingApprovalNotifications(enabled);

  async function handleLogout() {
    await logout();
    router.push("/");
    router.refresh();
  }

  if (variant === "auth") {
    return (
      <header className="header">
        <Link href="/" className="logo">전자결재 시스템</Link>
        <nav>
          <Link href="/auth">로그인</Link>
          <Link href="/signup">회원가입</Link>
        </nav>
      </header>
    );
  }

  return (
    <header className="header">
      <Link href="/" className="logo">전자결재 시스템</Link>
      <nav>
        {!loading && !isLoggedIn && <Link href="/auth">로그인</Link>}
        {isLoggedIn && user && (
          <>
            <span className="header-user-label">{user.department} · {user.positionLabel} {user.name}님</span>
            <Link href="/documents?tab=INBOX" className="header-messenger" aria-label={`결재 대기 ${approval.count}건`}>
              결재 알림
              {approval.count > 0 && <span className="header-badge">{approval.count > 99 ? "99+" : approval.count}</span>}
            </Link>
            {approval.canRequestPermission && (
              <button
                type="button"
                className="header-admin-link"
                onClick={() => { void approval.requestPermission(); }}
                title="새 결재 도착 시 브라우저 알림을 표시합니다."
              >
                알림 켜기
              </button>
            )}
            <Link href="/messenger" className="header-messenger">
              메신저
              {unread > 0 && <span className="header-badge">{unread > 99 ? "99+" : unread}</span>}
            </Link>
            {canManageUsers(user) && (
              <Link href="/admin" className="header-admin-link">조직 관리</Link>
            )}
            <Link href="/certificate">인증서</Link>
            <Link href="/mypage">마이페이지</Link>
            <a href="/auth" onClick={(event) => { event.preventDefault(); void handleLogout(); }}>로그아웃</a>
          </>
        )}
      </nav>
    </header>
  );
}
