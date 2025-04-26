package org.example.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Entity
@Table(name = "otp_config")
public class OtpConfig {
    @Id
    private Long id = 1L;

    private int codeLength = 6;
    private int expirationTimeMinutes = 5;

}
