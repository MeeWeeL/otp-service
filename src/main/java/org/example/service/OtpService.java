package org.example.service;

import lombok.RequiredArgsConstructor;
import org.example.model.OtpCode;
import org.example.repository.OtpCodeRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class OtpService {
    private final OtpCodeRepository otpCodeRepository;

    @Scheduled(fixedRate = 60000)
    public void expireOldCodes() {
        LocalDateTime expiryTime = LocalDateTime.now().minusMinutes(5);
        List<OtpCode> codes = otpCodeRepository.findExpiredCodes(expiryTime);
        codes.forEach(code -> code.setStatus("EXPIRED"));
        otpCodeRepository.saveAll(codes);
    }
}
