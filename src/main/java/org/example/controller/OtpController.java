package org.example.controller;

import jakarta.mail.MessagingException;
import org.example.dto.OtpRequest;
import org.example.model.OtpCode;
import org.example.model.OtpConfig;
import org.example.model.User;
import org.example.repository.OtpCodeRepository;
import org.example.repository.OtpConfigRepository;
import org.example.service.EmailService;
import org.example.service.FileService;
import org.example.service.SmsService;
import org.example.service.TelegramService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.Random;

@RestController
@RequestMapping("/api/otp")
public class OtpController {
    private final OtpCodeRepository otpCodeRepository;
    private final OtpConfigRepository otpConfigRepository;
    private final SmsService smsService;
    private final EmailService emailService;
    private final TelegramService telegramService;
    private final FileService fileService;

    public OtpController(
            OtpCodeRepository otpCodeRepository,
            OtpConfigRepository otpConfigRepository,
            SmsService smsService,
            EmailService emailService,
            TelegramService telegramService,
            FileService fileService
    ) {
        this.otpCodeRepository = otpCodeRepository;
        this.otpConfigRepository = otpConfigRepository;
        this.smsService = smsService;
        this.emailService = emailService;
        this.telegramService = telegramService;
        this.fileService = fileService;
    }

    @PostMapping("/generate")
    public ResponseEntity<?> generateOtp(
            @RequestBody OtpRequest request,
            Authentication authentication
    ) {
        try {
            User user = (User) authentication.getPrincipal();
            OtpConfig config = otpConfigRepository.findById(1L)
                    .orElseThrow(() -> new RuntimeException("OTP config not found"));

            String code = generateCode(config.getCodeLength());

            OtpCode otpCode = new OtpCode();
            otpCode.setCode(code);
            otpCode.setStatus("ACTIVE");
            otpCode.setCreatedAt(LocalDateTime.now());
            otpCode.setUser(user);
            otpCode.setOperationId(request.getOperationId());
            otpCodeRepository.save(otpCode);

            switch (request.getChannel().toUpperCase()) {
                case "SMS":
                    smsService.sendCode(request.getDestination(), code);
                    break;
                case "EMAIL":
                    emailService.sendCode(request.getDestination(), code);
                    break;
                case "TELEGRAM":
                    telegramService.sendCode(request.getDestination(), code);
                    break;
                case "FILE":
                    fileService.saveCodeToFile(code);
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported channel");
            }

            return ResponseEntity.ok("Code sent via " + request.getChannel());

        } catch (MessagingException e) {
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Email sending failed: " + e.getMessage());
        } catch (Exception e) {
            return ResponseEntity
                    .badRequest()
                    .body("Error: " + e.getMessage());
        }
    }

    private String generateCode(int length) {
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(random.nextInt(10));
        }
        return sb.toString();
    }
}
