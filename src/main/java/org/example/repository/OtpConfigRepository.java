package org.example.repository;

import org.example.model.OtpConfig;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OtpConfigRepository extends JpaRepository<OtpConfig, Long> {
}
