package org.example.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OtpValidationRequest {
    private String operationId;
    private String code;
}
