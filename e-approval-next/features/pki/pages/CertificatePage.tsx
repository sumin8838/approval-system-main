'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import Link from 'next/link'
import { useAuthState } from '@/lib/auth'
import { pkiApi } from '../api'
import { backupLocalPrivateKey, issueCertificate, loadSignerState, restorePrivateKeyBackup, SIGNER_STATE_MESSAGE, type SignerState } from '../certificate'
import { isCryptoAvailable, MIN_CERT_PASSWORD } from '../crypto'
import type { CertificateInfo } from '../types'
import { formatCertDate, groupHex } from '../utils'

/** 인증서 관리 (/certificate) — 공개 인증서와 암호화 개인키 백업 관리 */
export default function CertificatePage() {
  const { user } = useAuthState()
  const [state, setState] = useState<SignerState | null>(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [showForm, setShowForm] = useState(false)
  const [showPem, setShowPem] = useState(false)
  const [cryptoOk, setCryptoOk] = useState<boolean | null>(null)
  const [backupBusy, setBackupBusy] = useState(false)

  useEffect(() => setCryptoOk(isCryptoAvailable()), [])

  const load = useCallback(async (loginId: string) => {
    try {
      const s = await loadSignerState(loginId)
      setState(s)
      setShowForm(s.kind === 'no-cert')
      setError('')
    } catch (e) {
      setError(e instanceof Error ? e.message : '인증서 정보를 불러오지 못했습니다.')
    }
  }, [])

  useEffect(() => {
    if (user && cryptoOk) void load(user.loginId)
  }, [user, cryptoOk, load])

  const handleBackup = async () => {
    if (!user) return
    setBackupBusy(true)
    setError('')
    try {
      await backupLocalPrivateKey(user.loginId)
      setNotice('암호화된 개인키 백업을 서버 DB에 저장했습니다. 서버는 개인키를 복호화할 수 없습니다.')
    } catch (e) {
      setError(e instanceof Error ? e.message : '개인키 백업에 실패했습니다.')
    } finally {
      setBackupBusy(false)
    }
  }

  const handleRestore = async () => {
    if (!user) return
    setBackupBusy(true)
    setError('')
    try {
      await restorePrivateKeyBackup(user.loginId)
      await load(user.loginId)
      setNotice('서버의 암호화 백업을 이 브라우저에 복원했습니다. 서명할 때 인증서 암호를 입력하세요.')
    } catch (e) {
      setError(e instanceof Error ? e.message : '개인키 복원에 실패했습니다.')
    } finally {
      setBackupBusy(false)
    }
  }

  if (cryptoOk === false) {
    return <div className="apv-page"><div className="apv-alert apv-alert--error">이 브라우저에서는 암호 기능(Web Crypto)을 쓸 수 없습니다. http://localhost:3000 또는 https 주소로 접속하세요.</div></div>
  }
  if (!user || !state) return <div className="apv-page apv-center">{error || '불러오는 중...'}</div>

  const cert = state.kind === 'no-cert' ? null : state.cert

  return (
    <div className="apv-page">
      <nav className="apv-breadcrumb"><Link href="/">홈</Link> › 인증서 관리</nav>
      <h1 className="apv-title">전자서명 인증서 <span className="apv-title-sub">공개 인증서와 암호화 개인키 백업을 관리합니다</span></h1>
      {notice && <div className="apv-alert apv-alert--info">{notice}</div>}
      {error && <div className="apv-alert apv-alert--error">{error}</div>}
      {state.kind !== 'ready' && <div className="apv-alert">{SIGNER_STATE_MESSAGE[state.kind]}</div>}

      {cert && (
        <section className="apv-card">
          <div className="apv-card-title-row">
            <h2 className="apv-card-title">내 인증서 <span className={`pki-badge ${state.kind === 'ready' ? 'pki-badge--ok' : ''}`}>{state.kind === 'ready' ? '이 브라우저에서 사용 가능' : '복원 또는 재발급 필요'}</span></h2>
            {!showForm && <button className="apv-btn apv-btn--sm" onClick={() => setShowForm(true)}>재발급</button>}
          </div>
          <CertificateTable cert={cert} />
          <div className="pki-actions">
            <a className="apv-btn apv-btn--sm" href={pkiApi.certificateUrl(cert.serialNumber)} download>내 공개 인증서 내려받기 (.crt)</a>
            <a className="apv-btn apv-btn--sm apv-btn--ghost" href={pkiApi.caCertificateUrl()} download>루트 CA 인증서 내려받기</a>
            <button className="apv-btn apv-btn--sm apv-btn--ghost" onClick={() => setShowPem((v) => !v)}>{showPem ? 'PEM 닫기' : 'PEM 보기'}</button>
          </div>
          <div className="pki-actions">
            {state.kind === 'ready' && <button className="apv-btn apv-btn--sm apv-btn--primary" onClick={() => void handleBackup()} disabled={backupBusy}>{backupBusy ? '처리 중...' : '암호화 개인키 서버 백업'}</button>}
            {state.kind !== 'ready' && <button className="apv-btn apv-btn--sm apv-btn--primary" onClick={() => void handleRestore()} disabled={backupBusy}>{backupBusy ? '복원 중...' : '서버 백업에서 개인키 복원'}</button>}
          </div>
          {showPem && <pre className="pki-pre">{cert.pem}</pre>}
        </section>
      )}

      {showForm && <IssueForm loginId={user.loginId} reissue={cert !== null} onCancel={cert ? () => setShowForm(false) : undefined} onIssued={async (issued) => {
        setNotice(`인증서가 발급되고 암호화된 개인키 백업이 저장되었습니다. (일련번호 ${issued.serialNumber})`)
        await load(user.loginId)
      }} />}

      <section className="apv-card pki-explain">
        <h2 className="apv-card-title">어떻게 동작하나요?</h2>
        <ol>
          <li><strong>키 생성</strong> — 브라우저가 ECDSA P-256 키쌍을 만듭니다. 개인키(PKCS#8)는 인증서 암호로 PBKDF2 + AES-256-GCM 암호화됩니다.</li>
          <li><strong>인증서 발급</strong> — 공개키와 개인키 소유 증명을 서버에 보내면 사내 CA가 X.509 인증서를 발급합니다. 인증서에는 공개키가 포함되며 다른 사내 사용자가 서명 검증에 사용할 수 있습니다.</li>
          <li><strong>개인키 백업</strong> — 서버 DB에는 암호화된 개인키와 salt/IV/반복 횟수만 저장합니다. 인증서 암호는 서버로 보내거나 저장하지 않으므로 서버는 백업을 복호화할 수 없습니다.</li>
          <li><strong>결재 서명</strong> — 최초 서명 시 인증서 암호로 개인키를 잠금 해제합니다. 같은 탭에서는 최대 5분간 메모리의 추출 불가 키를 재사용하고, 만료·새로고침·로그아웃 후에는 다시 인증합니다.</li>
        </ol>
      </section>
    </div>
  )
}

function CertificateTable({ cert }: { cert: CertificateInfo }) {
  return (
    <table className="pki-table"><tbody>
      <tr><th>주체(소유자)</th><td>{cert.subject}</td></tr>
      <tr><th>발급자(CA)</th><td>{cert.issuer}</td></tr>
      <tr><th>일련번호</th><td className="pki-mono">{cert.serialNumber}</td></tr>
      <tr><th>유효기간</th><td>{formatCertDate(cert.notBefore)} ~ {formatCertDate(cert.notAfter)}</td></tr>
      <tr><th>알고리즘</th><td>{cert.algorithm}</td></tr>
      <tr><th>상태</th><td>{cert.statusLabel}</td></tr>
      <tr><th>지문(SHA-256)</th><td className="pki-mono pki-break">{groupHex(cert.fingerprintSha256)}</td></tr>
    </tbody></table>
  )
}

function IssueForm({ loginId, reissue, onCancel, onIssued }: {
  loginId: string
  reissue: boolean
  onCancel?: () => void
  onIssued: (cert: CertificateInfo) => Promise<void>
}) {
  const [loginPassword, setLoginPassword] = useState('')
  const [certPassword, setCertPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!loginPassword) return setError('본인 확인을 위해 로그인 비밀번호를 입력하세요.')
    if (certPassword.length < MIN_CERT_PASSWORD) return setError(`인증서 암호는 ${MIN_CERT_PASSWORD}자 이상이어야 합니다.`)
    if (certPassword !== confirm) return setError('인증서 암호 확인이 일치하지 않습니다.')
    if (certPassword === loginPassword) return setError('인증서 암호는 로그인 비밀번호와 다르게 정하세요.')
    if (reissue && !window.confirm('재발급하면 지금 인증서는 폐기됩니다. (이미 한 결재 서명은 계속 유효합니다) 진행할까요?')) return

    setBusy(true)
    setError('')
    try {
      const cert = await issueCertificate(loginId, loginPassword, certPassword)
      setLoginPassword('')
      setCertPassword('')
      setConfirm('')
      await onIssued(cert)
    } catch (err) {
      setError(err instanceof Error ? err.message : '발급에 실패했습니다.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="apv-card">
      <h2 className="apv-card-title">{reissue ? '인증서 재발급' : '인증서 발급'}</h2>
      <form className="pki-form" onSubmit={submit}>
        <label className="pki-field">로그인 비밀번호 (본인 확인)
          <input type="password" autoComplete="current-password" value={loginPassword} onChange={(e) => setLoginPassword(e.target.value)} disabled={busy} />
        </label>
        <label className="pki-field">인증서 암호 ({MIN_CERT_PASSWORD}자 이상)
          <input type="password" autoComplete="new-password" value={certPassword} onChange={(e) => setCertPassword(e.target.value)} disabled={busy} />
        </label>
        <label className="pki-field">인증서 암호 확인
          <input type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} disabled={busy} />
        </label>
        <p className="pki-muted">인증서 암호는 서버에 저장되지 않습니다. 분실하면 서버 백업이 있어도 복호화할 수 없으므로 재발급해야 합니다.</p>
        {error && <div className="pki-error">{error}</div>}
        <div className="pki-actions">
          {onCancel && <button type="button" className="apv-btn apv-btn--ghost" onClick={onCancel} disabled={busy}>취소</button>}
          <button type="submit" className="apv-btn apv-btn--primary" disabled={busy}>{busy ? '키 생성·발급 중...' : reissue ? '재발급' : '발급'}</button>
        </div>
      </form>
    </section>
  )
}
