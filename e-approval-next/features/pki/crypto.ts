/**
 * 결재 전자서명 암호 모듈 — 브라우저 Web Crypto API 사용
 *
 * 키      : ECDSA P-256
 * 서명    : ECDSA / SHA-256, 결과 r||s 64바이트
 * 키 보관 : PKCS#8 개인키를 인증서 암호의 PBKDF2 파생키로 AES-256-GCM 암호화한다.
 *           암호문은 IndexedDB 및 서버 DB에 백업할 수 있으며, 서버는 비밀번호를 받지 않는다.
 *           서명할 때만 브라우저 메모리에 추출 불가 CryptoKey로 가져온다.
 *
 * 서명 원문 형식은 서버(DocumentSignatureService.signedMessage)와 글자 하나까지 같아야 한다.
 */
import type { LocalKeyRecord } from './types'

const te = new TextEncoder()
const ECDSA_KEY = { name: 'ECDSA', namedCurve: 'P-256' } as const
const ECDSA_SIGN = { name: 'ECDSA', hash: 'SHA-256' } as const
const PBKDF2_ITERATIONS = 600_000
export const MIN_CERT_PASSWORD = 8

export function isCryptoAvailable(): boolean {
  return typeof window !== 'undefined' && window.isSecureContext && !!window.crypto?.subtle
}

export function bytesToB64(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data)
  let bin = ''
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return btoa(bin)
}

export function b64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export async function sha256Hex(text: string): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', te.encode(text))
  return Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, '0')).join('')
}

async function passwordKey(password: string, salt: Uint8Array<ArrayBuffer>, iterations: number): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, base,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
  )
}

function wrapAad(loginId: string): Uint8Array<ArrayBuffer> {
  return te.encode(`E-APPROVAL-USER-KEY v1|${loginId}`)
}

export interface NewKey {
  publicKey: string
  signingKey: CryptoKey
  wrapped: Pick<LocalKeyRecord, 'wrappedKey' | 'salt' | 'iv' | 'iterations'>
}

/** 새 키쌍을 만들고, 개인키를 인증서 암호로 암호화한다. */
export async function generateProtectedKey(loginId: string, certPassword: string): Promise<NewKey> {
  const pair = await crypto.subtle.generateKey(ECDSA_KEY, true, ['sign', 'verify'])
  const spki = await crypto.subtle.exportKey('spki', pair.publicKey)
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey))
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const aes = await passwordKey(certPassword, salt, PBKDF2_ITERATIONS)
  const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: wrapAad(loginId) }, aes, pkcs8)
  const signingKey = await crypto.subtle.importKey('pkcs8', pkcs8, ECDSA_KEY, false, ['sign'])
  pkcs8.fill(0)
  return {
    publicKey: bytesToB64(spki),
    signingKey,
    wrapped: {
      wrappedKey: bytesToB64(wrapped),
      salt: bytesToB64(salt),
      iv: bytesToB64(iv),
      iterations: PBKDF2_ITERATIONS,
    },
  }
}

/** 인증서 암호로 개인키를 풀어 서명용 키(추출 불가)로 가져온다. */
export async function unlockKey(record: LocalKeyRecord, certPassword: string): Promise<CryptoKey> {
  const aes = await passwordKey(certPassword, b64ToBytes(record.salt), record.iterations)
  let pkcs8: Uint8Array
  try {
    pkcs8 = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBytes(record.iv), additionalData: wrapAad(record.loginId) },
      aes,
      b64ToBytes(record.wrappedKey),
    ))
  } catch {
    throw new Error('인증서 암호가 올바르지 않습니다.')
  }
  try {
    return await crypto.subtle.importKey('pkcs8', pkcs8 as Uint8Array<ArrayBuffer>, ECDSA_KEY, false, ['sign'])
  } finally {
    pkcs8.fill(0)
  }
}

export async function signText(key: CryptoKey, text: string): Promise<string> {
  const sig = await crypto.subtle.sign(ECDSA_SIGN, key, te.encode(text))
  return bytesToB64(sig)
}

export function buildCertRequestMessage(loginId: string, challenge: string, publicKey: string): string {
  return ['E-APPROVAL-CERT-REQUEST v1', `login-id: ${loginId}`, `challenge: ${challenge}`, `public-key: ${publicKey}`].join('\n')
}

export type SignAction = 'SUBMIT' | 'APPROVE' | 'REJECT'

export interface SignedMessageInput {
  documentId: number
  documentNumber: string | null
  documentHash: string
  step: number
  action: SignAction
  comment: string | null
  previousSignatureSha256: string
  signer: string
  certificateSerial: string
  signedAt: string
}

export async function buildSignedMessage(m: SignedMessageInput): Promise<string> {
  return [
    'E-APPROVAL-SIGNATURE v2',
    `document-id: ${m.documentId}`,
    `document-number: ${m.documentNumber ?? ''}`,
    `document-sha256: ${m.documentHash}`,
    `step: ${m.step}`,
    `action: ${m.action}`,
    `comment-sha256: ${await sha256Hex(m.comment ?? '')}`,
    `previous-signature-sha256: ${m.previousSignatureSha256}`,
    `signer: ${m.signer}`,
    `certificate-serial: ${m.certificateSerial}`,
    `signed-at: ${m.signedAt}`,
  ].join('\n')
}
