package com.example.approval.pki.controller;

import com.example.approval.pki.dto.CertificateIssueRequest;
import com.example.approval.pki.dto.CertificateResponse;
import com.example.approval.pki.dto.ChallengeResponse;
import com.example.approval.pki.dto.MyCertificateResponse;
import com.example.approval.pki.dto.PrivateKeyBackupRequest;
import com.example.approval.pki.dto.PrivateKeyBackupResponse;
import com.example.approval.pki.service.CertificateService;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/** PKI 인증서 발급, 공개 인증서 조회 및 소유자 전용 개인키 암호문 백업 API. */
@RestController
@RequestMapping("/api/pki")
public class PkiController {

    private final CertificateService certificateService;

    public PkiController(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @GetMapping("/me")
    public MyCertificateResponse me(Authentication auth) {
        return certificateService.myCertificate(auth.getName());
    }

    @PostMapping("/challenge")
    public ChallengeResponse challenge(Authentication auth, HttpSession session) {
        return certificateService.newChallenge(auth.getName(), session);
    }

    @PostMapping("/certificates")
    @ResponseStatus(HttpStatus.CREATED)
    public CertificateResponse issue(Authentication auth, HttpSession session,
                                     @RequestBody(required = false) CertificateIssueRequest body) {
        return certificateService.issue(auth.getName(), body, session);
    }

    /** 다른 사용자에게 공개할 인증서. 로그인한 사내 사용자는 공개키를 조회할 수 있다. */
    @GetMapping("/users/{loginId}/certificate")
    public CertificateResponse publicCertificate(@PathVariable String loginId, Authentication auth) {
        return certificateService.publicCertificate(loginId);
    }

    /** 현재 로그인 사용자의 암호화 개인키 백업 저장/갱신 */
    @PutMapping("/me/private-key-backup")
    public PrivateKeyBackupResponse savePrivateKeyBackup(Authentication auth,
                                                         @RequestBody PrivateKeyBackupRequest body) {
        return certificateService.savePrivateKeyBackup(auth.getName(), body);
    }

    /** 현재 로그인 사용자의 암호화 개인키 백업 복원 */
    @GetMapping("/me/private-key-backup")
    public PrivateKeyBackupResponse privateKeyBackup(Authentication auth) {
        return certificateService.myPrivateKeyBackup(auth.getName());
    }

    /** 공개 인증서 파일(.crt). 인증서에는 공개키만 들어간다. */
    @GetMapping("/certificates/{serial}")
    public ResponseEntity<String> download(@PathVariable String serial) {
        return pemFile(certificateService.findBySerial(serial).getCertificatePem(), "user-" + serial + ".crt");
    }

    @GetMapping("/ca-certificate")
    public ResponseEntity<String> caCertificate() {
        return pemFile(certificateService.caCertificatePem(), "e-approval-root-ca.crt");
    }

    private static ResponseEntity<String> pemFile(String pem, String filename) {
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/x-x509-ca-cert"))
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(filename).build().toString())
                .body(pem);
    }
}
