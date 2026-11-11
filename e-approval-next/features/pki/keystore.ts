/**
 * 인증서 개인키 보관소 (브라우저 IndexedDB)
 *
 * - 개인키 PKCS#8 평문은 저장하지 않는다.
 * - "인증서 암호"로 AES-256-GCM 암호화한 암호문, salt, IV, 반복 횟수만 저장한다.
 * - 같은 암호문은 발급/백업 시 서버 DB에도 보관할 수 있다. 서버는 복호화 비밀번호를 갖지 않는다.
 * - 로그인 아이디마다 최신 키 1개를 보관한다.
 */
import type { LocalKeyRecord } from './types'

const DB_NAME = 'approval-pki'
const STORE = 'keys'
const VERSION = 1

let dbPromise: Promise<IDBDatabase> | null = null

function openDb(): Promise<IDBDatabase> {
  if (dbPromise) return dbPromise
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, VERSION)
    req.onupgradeneeded = () => {
      const db = req.result
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE, { keyPath: 'loginId' })
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => {
      dbPromise = null
      reject(req.error ?? new Error('IndexedDB 를 열 수 없습니다.'))
    }
  })
  return dbPromise
}

function run<T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return openDb().then((db) => new Promise<T>((resolve, reject) => {
    const tx = db.transaction(STORE, mode)
    const req = fn(tx.objectStore(STORE))
    tx.oncomplete = () => resolve(req.result)
    tx.onerror = () => reject(tx.error ?? new Error('인증서 저장소 오류'))
    tx.onabort = () => reject(tx.error ?? new Error('인증서 저장소 작업이 취소되었습니다.'))
  }))
}

export async function saveLocalKey(record: LocalKeyRecord): Promise<void> {
  await run('readwrite', (s) => s.put(record))
}

export async function getLocalKey(loginId: string): Promise<LocalKeyRecord | null> {
  const r = await run<LocalKeyRecord | undefined>('readonly', (s) => s.get(loginId))
  return r ?? null
}
