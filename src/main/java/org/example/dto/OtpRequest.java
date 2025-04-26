package org.example.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OtpRequest {
    private String operationId;
    private String channel; // SMS, EMAIL, TELEGRAM, FILE
    private String destination; // phone, email, chatId и т.д.
}
