# 전자결재 PKI / 결재 알림 보완 코드

이 폴더의 경로는 GitHub 저장소 `sumin8838/approval-system-main` 루트 기준입니다.
각 파일은 해당 경로의 전체 교체 파일입니다. 새 파일은 그대로 추가합니다.

## 반영 내용

1. X.509 인증서는 공개 조회 가능하게 유지합니다. `GET /api/pki/users/{loginId}/certificate`로 사내 사용자의 공개 인증서를 조회합니다. 기존 `GET /api/pki/certificates/{serial}`도 인증서 PEM만 내려줍니다.
2. 브라우저에서 PBKDF2-HMAC-SHA-256(기본 600,000회) + AES-256-GCM으로 암호화한 PKCS#8 개인키의 암호문, salt, IV, 반복 횟수만 DB에 저장합니다. 인증서 암호와 개인키 평문은 서버로 전송하지 않습니다.
3. 개인키 백업은 본인 로그인 세션으로만 업로드/다운로드할 수 있습니다. 서버는 개인키 백업을 복호화하거나 서명에 사용하지 않습니다.
4. 새 브라우저에서는 `/certificate`에서 서버 백업 복원을 누른 뒤, 결재 시 본인이 인증서 암호를 입력해 브라우저에서 복호화합니다.
5. 최초 인증 성공 후 현재 탭에서 최대 5분간 비추출 CryptoKey를 메모리에만 재사용합니다. 로그아웃 이벤트에서 캐시를 비우고 새로고침/탭 종료 시 메모리가 사라집니다.
6. 헤더는 기존 `/api/documents/inbox`를 15초마다 조회해 대기 건수를 표시하고, 브라우저 알림 권한이 허용된 상태에서 대기 건수가 늘면 OS 알림을 발생시킵니다.
7. 실제 문서 본문은 기존 `DocumentWritePage.tsx`의 웹 입력 양식에서 작성됩니다. 첨부파일은 보조자료로 유지됩니다. 따라서 문서 작성 화면은 기존 웹 화면을 계속 사용하며 새 데스크톱 문서 편집 기능은 추가하지 않습니다.

## 전체 파일 교체 / 추가 목록

- 교체: `backend/src/main/java/com/example/approval/pki/domain/UserCertificate.java`
- 교체: `backend/src/main/java/com/example/approval/pki/dto/CertificateIssueRequest.java`
- 추가: `backend/src/main/java/com/example/approval/pki/dto/PrivateKeyBackupRequest.java`
- 추가: `backend/src/main/java/com/example/approval/pki/dto/PrivateKeyBackupResponse.java`
- 교체: `backend/src/main/java/com/example/approval/pki/repository/UserCertificateRepository.java`
- 교체: `backend/src/main/java/com/example/approval/pki/service/CertificateService.java`
- 교체: `backend/src/main/java/com/example/approval/pki/controller/PkiController.java`
- 교체: `e-approval-next/features/pki/types.ts`
- 교체: `e-approval-next/features/pki/crypto.ts` (키 보관 방식 설명 갱신)
- 교체: `e-approval-next/features/pki/keystore.ts` (로컬 암호문 보관 설명 갱신)
- 교체: `e-approval-next/features/pki/api.ts`
- 교체: `e-approval-next/features/pki/certificate.ts`
- 교체: `e-approval-next/features/pki/useCertificateSigner.tsx`
- 교체: `e-approval-next/features/pki/pages/CertificatePage.tsx`
- 추가: `e-approval-next/features/approval/usePendingApprovalNotifications.ts`
- 교체: `e-approval-next/components/Header.tsx`
- 교체: `e-approval-next/lib/auth.ts`

## DB

현재 저장소 README의 설정처럼 Hibernate `ddl-auto=update`가 활성화되어 있으면 엔티티 필드에 맞춰 컬럼이 추가됩니다. 운영 환경에서 자동 DDL을 끄는 경우 `docs/approval-pki-backup-migration.sql`을 적용하세요.

## API

- `POST /api/pki/certificates`: 인증서 발급 및 암호화 개인키 백업 저장
- `GET /api/pki/users/{loginId}/certificate`: 공개 인증서 조회
- `PUT /api/pki/me/private-key-backup`: 본인의 암호문 백업 업로드/갱신
- `GET /api/pki/me/private-key-backup`: 본인의 암호문 백업 다운로드
- 기존 `/api/documents/inbox`: 결재 대기 문서 조회 (알림에서 재사용)

## 운영 전 보안 체크

- 운영 환경은 반드시 HTTPS를 사용해야 합니다. Web Crypto는 localhost 또는 secure context에서만 동작합니다.
- 인증서 암호는 로그인 비밀번호와 다르게, 충분히 길고 추측하기 어렵게 정하세요. 암호를 분실하면 암호화 백업을 복원해도 개인키를 열 수 없습니다.
- 개인키 암호문이 DB에 저장되므로 DB 접근 통제, 백업 파일 암호화, DB 접근 감사가 필요합니다.
- 현재 결재 알림은 웹 앱이 열려 있을 때 동작하는 15초 폴링입니다. 브라우저/앱이 완전히 종료된 상태에서도 알림을 보내려면 별도의 Web Push 구독, VAPID 키, Service Worker, 서버 푸시 발송 기능이 추가로 필요합니다.
- `SecurityConfig`의 CSRF 비활성화는 저장소 README의 기존 TODO입니다. 외부 배포 전에는 세션 인증에 CSRF 보호를 활성화해야 합니다.
