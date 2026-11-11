'use client'

import { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import CertPasswordDialog from './components/CertPasswordDialog'
import {
  clearUnlockedSigningKeys,
  hasUnlockedSigningKey,
  loadSignerState,
  SIGNER_STATE_MESSAGE,
  type SignerState,
} from './certificate'
import { isCryptoAvailable } from './crypto'
import type { LocalKeyRecord } from './types'

type ReadySigner = Extract<SignerState, { kind: 'ready' }>

interface SignRequest {
  title: string
  description: string
  confirmLabel: string
  /** 처음에는 암호를 전달하고, 잠금 해제된 5분 동안에는 빈 문자열을 전달한다. */
  onSign: (record: LocalKeyRecord, certPassword: string) => Promise<void>
  onCancel?: () => void
}

/** 인증서 상태 확인과 전자서명 인증 UI. 잠금 해제 상태는 현재 탭 메모리에서 최대 5분 유지한다. */
export function useCertificateSigner(loginId: string | undefined) {
  const [request, setRequest] = useState<(SignRequest & { ready: ReadySigner }) | null>(null)
  const [problemText, setProblemText] = useState('')

  const prepare = useCallback(async (): Promise<ReadySigner | null> => {
    setProblemText('')
    if (!isCryptoAvailable()) {
      setProblemText('이 브라우저에서는 전자서명을 할 수 없습니다. http://localhost:3000 또는 https 주소로 접속하세요.')
      return null
    }
    if (!loginId) {
      setProblemText('로그인 정보를 불러오지 못했습니다. 새로고침 후 다시 시도하세요.')
      return null
    }
    const state = await loadSignerState(loginId)
    if (state.kind !== 'ready') {
      setProblemText(SIGNER_STATE_MESSAGE[state.kind])
      return null
    }
    return state
  }, [loginId])

  const open = useCallback((ready: ReadySigner, req: SignRequest) => {
    setProblemText('')
    // 직전에 인증했고 5분이 지나지 않았다면 비밀번호 입력 창을 다시 띄우지 않는다.
    if (hasUnlockedSigningKey(ready.record.loginId, ready.record.serialNumber)) {
      void req.onSign(ready.record, '').catch((error: unknown) => {
        setProblemText(error instanceof Error ? error.message : '전자서명에 실패했습니다.')
      })
      return
    }
    setRequest({ ...req, ready })
  }, [])

  // 로그아웃하면 메모리에 남아 있던 CryptoKey도 즉시 폐기한다.
  useEffect(() => {
    const clear = () => clearUnlockedSigningKeys(loginId)
    window.addEventListener('approval-logout', clear)
    return () => window.removeEventListener('approval-logout', clear)
  }, [loginId])

  const dialog = request ? (
    <CertPasswordDialog
      title={request.title}
      description={`${request.description} 최초 인증 후 5분 동안은 같은 브라우저에서 추가 입력 없이 서명할 수 있습니다.`}
      cert={request.ready.cert}
      confirmLabel={request.confirmLabel}
      onSubmit={async (certPassword) => {
        await request.onSign(request.ready.record, certPassword)
        setRequest(null)
      }}
      onClose={() => {
        setRequest(null)
        request.onCancel?.()
      }}
    />
  ) : null

  const problem = problemText ? (
    <div className="apv-alert apv-no-print">
      {problemText} <Link href="/certificate">인증서 관리로 이동 →</Link>
    </div>
  ) : null

  return { prepare, open, dialog, problem, clearProblem: () => setProblemText('') }
}
