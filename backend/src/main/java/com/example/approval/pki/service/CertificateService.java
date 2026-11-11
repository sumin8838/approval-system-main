package com.example.approval.pki.service;

import com.example.approval.domain.User;
import com.example.approval.domain.UserStatus;
import com.example.approval.exception.ApiException;
import com.example.approval.pki.crypto.PkiCrypto;
import com.example.approval.pki.domain.CertificateStatus;
import com.example.approval.pki.domain.UserCertificate;
import com.example.approval.pki.dto.CertificateIssueRequest;
import com.example.approval.pki.dto.CertificateResponse;
import com.example.approval.pki.dto.ChallengeResponse;
import com.example.approval.pki.dto.MyCertificateResponse;
import com.example.approval.pki.dto.PrivateKeyBackupRequest;
import com.example.approval.pki.dto.PrivateKeyBackupResponse;
import com.example.approval.pki.repository.UserCertificateRepository;
import com.example.approval.repository.UserRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.security.auth.x500.X500Principal;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Arrays;

/** 사용자 인증서 발급·조회와 암호화된 개인키 백업 관리 */
@Service
public class CertificateService {

    private static final String CHALLENGE_ATTR = "pki.challenge";
    private static final long CHALLENGE_TTL_SECONDS = 300;
    private static final int MIN_PBKDF2_ITERATIONS = 600_000;
    private static final int MAX_PBKDF2_ITERATIONS = 2_000_000;
    private static final int MAX_CIPHERTEXT_BYTES = 8_192;

    private final UserCertificateRepository certificateRepository;
    private final UserRepository userRepository;
    private final CaService caService;
    private final PasswordEncoder passwordEncoder;

    public CertificateService(UserCertificateRepository certificateRepository, UserRepository userRepository,
                              CaService caService, PasswordEncoder passwordEncoder) {
        this.certificateRepository = certificateRepository;
        this.userRepository = userRepository;
        this.caService = caService;
        this.passwordEncoder = passwordEncoder;
    }

    /** 발급 요청문. 브라우저(features/pki/crypto.ts)와 글자 하나까지 같아야 한다. */
    public static String requestMessage(String loginId, String challenge, String publicKey) {
        return "E-APPROVAL-CERT-REQUEST v1\n"
                + "login-id: " + loginId + "\n"
                + "challenge: " + challenge + "\n"
                + "public-key: " + publicKey;
    }

    private record Challenge(String value, Instant expiresAt) implements java.io.Serializable {}

    public ChallengeResponse newChallenge(String loginId, HttpSession session) {
        String value = Base64.getUrlEncoder().withoutPadding().encodeToString(PkiCrypto.randomBytes(32));
        session.setAttribute(CHALLENGE_ATTR, new Challenge(value, Instant.now().plusSeconds(CHALLENGE_TTL_SECONDS)));
        return new ChallengeResponse(value, loginId);
    }

    @Transactional
    public CertificateResponse issue(String loginId, CertificateIssueRequest req, HttpSession session) {
        User user = currentUser(loginId);
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new ApiException(HttpStatus.FORBIDDEN, "승인된 계정만 인증서를 발급받을 수 있습니다.");
        }
        if (req == null || isBlank(req.publicKey()) || isBlank(req.proof()) || isBlank(req.loginPassword())) {
            throw badRequest("발급 요청 정보가 부족합니다.");
        }
        validateEncryptedBackup(req.encryptedPrivateKey(), req.privateKeySalt(), req.privateKeyIv(),
                req.privateKeyIterations());

        if (!passwordEncoder.matches(req.loginPassword(), user.getPassword())) {
            throw badRequest("로그인 비밀번호가 올바르지 않습니다.");
        }

        // challenge는 한 번만 사용한다.
        Object saved = session.getAttribute(CHALLENGE_ATTR);
        session.removeAttribute(CHALLENGE_ATTR);
        if (!(saved instanceof Challenge challenge) || Instant.now().isAfter(challenge.expiresAt())) {
            throw badRequest("발급 요청 시간이 지났습니다. 다시 시도하세요.");
        }

        PublicKey publicKey;
        try {
            publicKey = PkiCrypto.parsePublicKey(req.publicKey());
        } catch (GeneralSecurityException e) {
            throw badRequest("공개키 형식이 올바르지 않습니다.");
        }
        String message = requestMessage(user.getLoginId(), challenge.value(), req.publicKey());
        if (!PkiCrypto.verifyBrowserSignature(publicKey, message, req.proof())) {
            throw badRequest("개인키 소유 증명(서명) 검증에 실패했습니다.");
        }

        certificateRepository.findByUserAndStatus(user, CertificateStatus.VALID).forEach(UserCertificate::revoke);
        X509Certificate cert = caService.issue(user, publicKey);
        UserCertificate entity = new UserCertificate(
                user,
                PkiCrypto.serialHex(cert.getSerialNumber()),
                cert.getSubjectX500Principal().getName(X500Principal.RFC2253),
                PkiCrypto.toPem(cert),
                toLocal(cert.getNotBefore().toInstant()),
                toLocal(cert.getNotAfter().toInstant()));
        entity.saveEncryptedPrivateKey(req.publicKey(), req.encryptedPrivateKey(), req.privateKeySalt(),
                req.privateKeyIv(), req.privateKeyIterations());
        certificateRepository.save(entity);
        return CertificateResponse.from(entity);
    }

    /** 내 현재 인증서 */
    @Transactional(readOnly = true)
    public MyCertificateResponse myCertificate(String loginId) {
        User user = currentUser(loginId);
        return new MyCertificateResponse(certificateRepository
                .findFirstByUserAndStatusOrderByIdDesc(user, CertificateStatus.VALID)
                .filter(UserCertificate::isUsableNow)
                .map(CertificateResponse::from)
                .orElse(null));
    }

    /** 조직 내 다른 사용자의 공개 인증서 조회. 암호화 개인키 컬럼은 반환하지 않는다. */
    @Transactional(readOnly = true)
    public CertificateResponse publicCertificate(String loginId) {
        return certificateRepository
                .findFirstByUser_LoginIdAndStatusOrderByIdDesc(loginId, CertificateStatus.VALID)
                .filter(UserCertificate::isUsableNow)
                .map(CertificateResponse::from)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "사용자의 유효한 공개 인증서가 없습니다."));
    }

    /** 기존 인증서에서 생성된 브라우저 암호문을 서버 DB에 백업한다. 소유자만 호출 가능. */
    @Transactional
    public PrivateKeyBackupResponse savePrivateKeyBackup(String loginId, PrivateKeyBackupRequest req) {
        if (req == null) throw badRequest("개인키 백업 정보가 없습니다.");
        validateEncryptedBackup(req.wrappedKey(), req.salt(), req.iv(), req.iterations());
        if (isBlank(req.serialNumber()) || isBlank(req.publicKey())) {
            throw badRequest("인증서 일련번호와 공개키가 필요합니다.");
        }

        User user = currentUser(loginId);
        UserCertificate certificate = certificateRepository
                .findFirstByUserAndStatusOrderByIdDesc(user, CertificateStatus.VALID)
                .filter(UserCertificate::isUsableNow)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "유효한 인증서가 없습니다."));

        if (!certificate.getSerialNumber().equalsIgnoreCase(req.serialNumber())) {
            throw new ApiException(HttpStatus.CONFLICT, "현재 인증서와 백업 대상 인증서가 일치하지 않습니다.");
        }
        verifyPublicKeyMatchesCertificate(req.publicKey(), certificate);
        certificate.saveEncryptedPrivateKey(req.publicKey(), req.wrappedKey(), req.salt(), req.iv(), req.iterations());
        return PrivateKeyBackupResponse.from(certificate);
    }

    /** 로그인 사용자 본인의 암호문만 반환한다. 관리자/다른 사용자의 백업은 조회할 수 없다. */
    @Transactional(readOnly = true)
    public PrivateKeyBackupResponse myPrivateKeyBackup(String loginId) {
        User user = currentUser(loginId);
        UserCertificate certificate = certificateRepository
                .findFirstByUserAndStatusOrderByIdDesc(user, CertificateStatus.VALID)
                .filter(UserCertificate::isUsableNow)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "유효한 인증서가 없습니다."));
        if (!certificate.hasEncryptedPrivateKey()) {
            throw new ApiException(HttpStatus.NOT_FOUND, "서버에 암호화된 개인키 백업이 없습니다. 인증서 관리에서 백업하세요.");
        }
        return PrivateKeyBackupResponse.from(certificate);
    }

    @Transactional(readOnly = true)
    public UserCertificate findBySerial(String serial) {
        return certificateRepository.findBySerialNumber(serial == null ? "" : serial.toUpperCase())
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "인증서를 찾을 수 없습니다."));
    }

    public String caCertificatePem() { return PkiCrypto.toPem(caService.certificate()); }
    public X509Certificate caCertificate() { return caService.certificate(); }

    private void verifyPublicKeyMatchesCertificate(String publicKeyBase64, UserCertificate certificate) {
        try {
            PublicKey submitted = PkiCrypto.parsePublicKey(publicKeyBase64);
            PublicKey certified = PkiCrypto.fromPem(certificate.getCertificatePem()).getPublicKey();
            if (!Arrays.equals(submitted.getEncoded(), certified.getEncoded())) {
                throw badRequest("백업 공개키가 현재 인증서의 공개키와 일치하지 않습니다.");
            }
        } catch (GeneralSecurityException e) {
            throw badRequest("공개키 형식이 올바르지 않습니다.");
        }
    }

    /** base64 형식, AES-GCM IV/salt 길이, KDF 반복 횟수를 검사한다. */
    private void validateEncryptedBackup(String encrypted, String salt, String iv, Integer iterations) {
        if (isBlank(encrypted) || encrypted.length() > 12_000 || isBlank(salt) || isBlank(iv)) {
            throw badRequest("암호화된 개인키 백업 정보가 올바르지 않습니다.");
        }
        if (iterations == null || iterations < MIN_PBKDF2_ITERATIONS || iterations > MAX_PBKDF2_ITERATIONS) {
            throw badRequest("개인키 암호화 반복 횟수가 허용 범위를 벗어났습니다.");
        }
        try {
            byte[] ciphertext = Base64.getDecoder().decode(encrypted);
            byte[] saltBytes = Base64.getDecoder().decode(salt);
            byte[] ivBytes = Base64.getDecoder().decode(iv);
            if (ciphertext.length < 32 || ciphertext.length > MAX_CIPHERTEXT_BYTES
                    || saltBytes.length != 16 || ivBytes.length != 12) {
                throw badRequest("개인키 암호문 길이가 올바르지 않습니다.");
            }
        } catch (IllegalArgumentException e) {
            throw badRequest("개인키 백업 값은 Base64 형식이어야 합니다.");
        }
    }

    private User currentUser(String loginId) {
        return userRepository.findByLoginId(loginId)
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "로그인이 필요합니다."));
    }

    private static LocalDateTime toLocal(Instant i) {
        return LocalDateTime.ofInstant(i, ZoneId.systemDefault());
    }

    private static boolean isBlank(String s) { return s == null || s.isBlank(); }
    private static ApiException badRequest(String m) { return new ApiException(HttpStatus.BAD_REQUEST, m); }
}
