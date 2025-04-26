package org.example.repository;

import org.example.model.OtpCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface OtpCodeRepository extends JpaRepository<OtpCode, Long> {
    Optional<OtpCode> findByCodeAndOperationId(String code, String operationId);

    @Query("SELECT o FROM OtpCode o WHERE o.status = 'ACTIVE' AND o.createdAt < ?1")
    List<OtpCode> findExpiredCodes(LocalDateTime expiryTime);
}
