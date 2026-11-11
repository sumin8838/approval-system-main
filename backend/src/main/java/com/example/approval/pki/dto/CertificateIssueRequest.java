package com.example.approval.pki.dto;

/**
 * 인증서 발급 요청.
 * encryptedPrivateKey는 인증서 암호로 브라우저에서 AES-GCM 암호화한 PKCS#8 개인키다.
 * 서버는 암호문만 저장하며 복호화 비밀번호는 받지 않는다.
 */
public record CertificateIssueRequest(
        String publicKey,
        String proof,
        String loginPassword,
        String encryptedPrivateKey,
        String privateKeySalt,
        String privateKeyIv,
        Integer privateKeyIterations
) {}
