/** 인증서 발급, 암호화 개인키 백업/복구, 문서 전자서명 흐름 */
import { pkiApi } from './api'
import {
  buildCertRequestMessage,
  buildSignedMessage,
  generateProtectedKey,
  sha256Hex,
  signText,
  unlockKey,
  type SignAction,
} from './crypto'
import { getLocalKey, saveLocalKey } from './keystore'
import type { CertificateInfo, LocalKeyRecord, PrivateKeyBackup } from './types'

/**
 * 암호를 한 번 입력해 잠금 해제한 키를 현재 탭의 메모리에서만 5분간 재사용한다.
 * 새로고침/탭 종료/로그아웃 시 사라지고, IndexedDB나 서버에 평문 키를 저장하지 않는다.
 */
const UNLOCK_TTL_MS = 5 * 60 * 1000
const unlockedKeys = new Map<string, { serialNumber: string; key: CryptoKey; expiresAt: number; timer: ReturnType<typeof setTimeout> }>()

function cacheId(loginId: string): string {
  return loginId
}

export function hasUnlockedSigningKey(loginId: string, serialNumber: string): boolean {
  const cached = unlockedKeys.get(cacheId(loginId))
  if (!cached) return false
  if (cached.expiresAt <= Date.now() || cached.serialNumber !== serialNumber) {
    unlockedKeys.delete(cacheId(loginId))
    return false
  }
  return true
}

export function clearUnlockedSigningKeys(loginId?: string): void {
  if (loginId) {
    const cached = unlockedKeys.get(cacheId(loginId))
    if (cached) clearTimeout(cached.timer)
    unlockedKeys.delete(cacheId(loginId))
  } else {
    for (const cached of unlockedKeys.values()) clearTimeout(cached.timer)
    unlockedKeys.clear()
  }
}

async function getSigningKey(record: LocalKeyRecord, certPassword: string): Promise<CryptoKey> {
  const cached = unlockedKeys.get(cacheId(record.loginId))
  if (cached && cached.expiresAt > Date.now() && cached.serialNumber === record.serialNumber) {
    return cached.key
  }
  unlockedKeys.delete(cacheId(record.loginId))
  if (!certPassword) throw new Error('인증서 잠금이 만료되었습니다. 다시 인증하세요.')
  const key = await unlockKey(record, certPassword)
  const entry: { serialNumber: string; key: CryptoKey; expiresAt: number; timer: ReturnType<typeof setTimeout> } = {
    serialNumber: record.serialNumber,
    key,
    expiresAt: Date.now() + UNLOCK_TTL_MS,
    timer: 0 as unknown as ReturnType<typeof setTimeout>,
  }
  entry.timer = setTimeout(() => {
    if (unlockedKeys.get(cacheId(record.loginId)) === entry) unlockedKeys.delete(cacheId(record.loginId))
  }, UNLOCK_TTL_MS)
  unlockedKeys.set(cacheId(record.loginId), entry)
  return key
}

/** 최초 인증서 발급. 암호화된 개인키 암호문도 서버 DB에 함께 백업한다. */
export async function issueCertificate(
  loginId: string,
  loginPassword: string,
  certPassword: string,
): Promise<CertificateInfo> {
  const key = await generateProtectedKey(loginId, certPassword)
  const { challenge } = await pkiApi.challenge()
  const proof = await signText(key.signingKey, buildCertRequestMessage(loginId, challenge, key.publicKey))
  const cert = await pkiApi.issue(key.publicKey, proof, loginPassword, key.wrapped)
  await saveLocalKey({
    loginId,
    serialNumber: cert.serialNumber,
    publicKey: key.publicKey,
    ...key.wrapped,
    createdAt: new Date().toISOString(),
  })
  return cert
}

export type SignerState =
  | { kind: 'ready'; cert: CertificateInfo; record: LocalKeyRecord }
  | { kind: 'no-cert' }
  | { kind: 'no-local-key'; cert: CertificateInfo }
  | { kind: 'mismatch'; cert: CertificateInfo; record: LocalKeyRecord }

export async function loadSignerState(loginId: string): Promise<SignerState> {
  const [{ certificate }, record] = await Promise.all([pkiApi.me(), getLocalKey(loginId)])
  if (!certificate) return { kind: 'no-cert' }
  if (!record) return { kind: 'no-local-key', cert: certificate }
  if (record.serialNumber !== certificate.serialNumber) return { kind: 'mismatch', cert: certificate, record }
  return { kind: 'ready', cert: certificate, record }
}

export const SIGNER_STATE_MESSAGE: Record<Exclude<SignerState['kind'], 'ready'>, string> = {
  'no-cert': '결재하려면 먼저 전자서명 인증서를 발급받아야 합니다.',
  'no-local-key': '이 브라우저에는 개인키가 없습니다. 서버에 저장된 암호화 백업을 복원하거나 인증서를 재발급하세요.',
  mismatch: '이 브라우저의 개인키와 현재 인증서가 일치하지 않습니다. 서버 백업을 복원하거나 재발급하세요.',
}

export interface SigningContext {
  step: number
  documentNumber: string
  documentContent: string
  previousSignatureSha256: string
}

export interface DocumentSignature {
  signature: string
  signedAt: string
  certificateSerial: string
}

/** 구형 인증서 사용자가 현재 브라우저에 있는 개인키 암호문을 서버에 업로드한다. */
export async function backupLocalPrivateKey(loginId: string): Promise<void> {
  const record = await getLocalKey(loginId)
  if (!record) throw new Error('이 브라우저에 백업할 개인키가 없습니다.')
  await pkiApi.savePrivateKeyBackup({
    serialNumber: record.serialNumber,
    publicKey: record.publicKey,
    wrappedKey: record.wrappedKey,
    salt: record.salt,
    iv: record.iv,
    iterations: record.iterations,
  })
}

/** 새 브라우저/PC에서 소유자의 암호화 백업을 복원한다. 복호화는 서명 시 사용자 암호로 수행한다. */
export async function restorePrivateKeyBackup(loginId: string): Promise<void> {
  const backup: PrivateKeyBackup = await pkiApi.privateKeyBackup()
  await saveLocalKey({
    loginId,
    serialNumber: backup.serialNumber,
    publicKey: backup.publicKey,
    wrappedKey: backup.wrappedKey,
    salt: backup.salt,
    iv: backup.iv,
    iterations: backup.iterations,
    createdAt: new Date().toISOString(),
  })
}

/** 문서 서명 (상신·승인·반려 공통). 잠금 해제된 키가 있으면 5분 동안 비밀번호 입력을 생략한다. */
export async function signDocumentAction(args: {
  record: LocalKeyRecord
  certPassword: string
  documentId: number
  signing: SigningContext
  action: SignAction
  comment: string | null
}): Promise<DocumentSignature> {
  const key = await getSigningKey(args.record, args.certPassword)
  const signedAt = new Date().toISOString()
  const message = await buildSignedMessage({
    documentId: args.documentId,
    documentNumber: args.signing.documentNumber,
    documentHash: await sha256Hex(args.signing.documentContent),
    step: args.signing.step,
    action: args.action,
    comment: args.comment,
    previousSignatureSha256: args.signing.previousSignatureSha256,
    signer: args.record.loginId,
    certificateSerial: args.record.serialNumber,
    signedAt,
  })
  return {
    signature: await signText(key, message),
    signedAt,
    certificateSerial: args.record.serialNumber,
  }
}

// Header에서 로그아웃해도 현재 탭 메모리에 남은 서명 키를 제거한다.
if (typeof window !== 'undefined') {
  window.addEventListener('approval-logout', () => clearUnlockedSigningKeys())
}
