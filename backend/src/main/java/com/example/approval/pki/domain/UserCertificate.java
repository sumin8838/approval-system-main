package com.example.approval.pki.domain;

import com.example.approval.domain.User;
import jakarta.persistence.*;

import java.time.LocalDateTime;

/**
 * 사용자에게 발급한 X.509 인증서와 암호화된 개인키 백업 메타데이터.
 * 인증서/공개키는 공개 검증용이다. 개인키는 브라우저에서 인증서 암호로
 * AES-256-GCM 암호화한 값만 저장하며 서버는 이를 복호화하거나 서명에 사용하지 않는다.
 */
@Entity
@Table(name = "user_certificates")
public class UserCertificate {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id")
    private User user;

    @Column(nullable = false, unique = true, length = 40)
    private String serialNumber;

    @Column(nullable = false, length = 300)
    private String subjectDn;

    @Column(nullable = false, length = 2000)
    private String certificatePem;

    @Column(nullable = false)
    private LocalDateTime notBefore;

    @Column(nullable = false)
    private LocalDateTime notAfter;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private CertificateStatus status;

    private LocalDateTime revokedAt;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    // 암호문만 저장. 개인키 평문과 인증서 비밀번호는 DB에 저장하지 않는다.
    @Column(name = "encrypted_private_key", length = 12000)
    private String encryptedPrivateKey;

    @Column(name = "private_key_public_key", length = 2000)
    private String privateKeyPublicKey;

    @Column(name = "private_key_salt", length = 128)
    private String privateKeySalt;

    @Column(name = "private_key_iv", length = 64)
    private String privateKeyIv;

    @Column(name = "private_key_iterations")
    private Integer privateKeyIterations;

    protected UserCertificate() {}

    public UserCertificate(User user, String serialNumber, String subjectDn, String certificatePem,
                           LocalDateTime notBefore, LocalDateTime notAfter) {
        this.user = user;
        this.serialNumber = serialNumber;
        this.subjectDn = subjectDn;
        this.certificatePem = certificatePem;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.status = CertificateStatus.VALID;
        this.createdAt = LocalDateTime.now();
    }

    public void saveEncryptedPrivateKey(String publicKey, String encryptedPrivateKey,
                                        String salt, String iv, int iterations) {
        this.privateKeyPublicKey = publicKey;
        this.encryptedPrivateKey = encryptedPrivateKey;
        this.privateKeySalt = salt;
        this.privateKeyIv = iv;
        this.privateKeyIterations = iterations;
    }

    public boolean hasEncryptedPrivateKey() {
        return encryptedPrivateKey != null && !encryptedPrivateKey.isBlank();
    }

    public void revoke() {
        if (status == CertificateStatus.REVOKED) return;
        this.status = CertificateStatus.REVOKED;
        this.revokedAt = LocalDateTime.now();
    }

    public boolean isOwnedBy(User u) { return user.getId().equals(u.getId()); }

    public boolean isUsableNow() {
        LocalDateTime now = LocalDateTime.now();
        return status == CertificateStatus.VALID && !now.isBefore(notBefore) && now.isBefore(notAfter);
    }

    public Long getId() { return id; }
    public User getUser() { return user; }
    public String getSerialNumber() { return serialNumber; }
    public String getSubjectDn() { return subjectDn; }
    public String getCertificatePem() { return certificatePem; }
    public LocalDateTime getNotBefore() { return notBefore; }
    public LocalDateTime getNotAfter() { return notAfter; }
    public CertificateStatus getStatus() { return status; }
    public LocalDateTime getRevokedAt() { return revokedAt; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public String getEncryptedPrivateKey() { return encryptedPrivateKey; }
    public String getPrivateKeyPublicKey() { return privateKeyPublicKey; }
    public String getPrivateKeySalt() { return privateKeySalt; }
    public String getPrivateKeyIv() { return privateKeyIv; }
    public Integer getPrivateKeyIterations() { return privateKeyIterations; }
}
