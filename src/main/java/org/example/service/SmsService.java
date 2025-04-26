package org.example.service;

import org.jsmpp.InvalidResponseException;
import org.jsmpp.PDUException;
import org.jsmpp.bean.*;
import org.jsmpp.extra.NegativeResponseException;
import org.jsmpp.extra.ResponseTimeoutException;
import org.jsmpp.session.BindParameter;
import org.jsmpp.session.SMPPSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Service
public class SmsService {
    private static final Logger logger = LoggerFactory.getLogger(SmsService.class);

    @Value("${smpp.host}")
    private String host;
    @Value("${smpp.port}")
    private int port;
    @Value("${smpp.system_id}")
    private String systemId;
    @Value("${smpp.password}")
    private String password;
    @Value("${smpp.source_addr}")
    private String sourceAddress;

    public void sendCode(String phoneNumber, String code) {
        SMPPSession session = new SMPPSession();
        try {
            session.connectAndBind(
                    host, port,
                    new BindParameter(
                            BindType.BIND_TRX,
                            systemId,
                            password,
                            "cp",
                            TypeOfNumber.UNKNOWN,
                            NumberingPlanIndicator.UNKNOWN,
                            null
                    )
            );

            submitMessage(session, phoneNumber, code);

        } catch (IOException e) {
            handleError("Ошибка ввода-вывода", e);
        } catch (PDUException e) {
            handleError("Ошибка PDU", e);
        } catch (ResponseTimeoutException e) {
            handleError("Таймаут ответа", e);
        } catch (InvalidResponseException e) {
            handleError("Неверный ответ", e);
        } catch (NegativeResponseException e) {
            handleError("Отрицательный ответ: " + e.getCommandStatus(), e);
        } catch (Exception e) {
            handleError("Неизвестная ошибка", e);
        } finally {
            closeSession(session);
        }
    }

    private void submitMessage(SMPPSession session, String phone, String code)
            throws PDUException, ResponseTimeoutException, InvalidResponseException,
            NegativeResponseException, IOException {

        String message = "Ваш код: " + code;
        session.submitShortMessage(
                "CMT",
                TypeOfNumber.INTERNATIONAL,
                NumberingPlanIndicator.UNKNOWN,
                sourceAddress,
                TypeOfNumber.INTERNATIONAL,
                NumberingPlanIndicator.UNKNOWN,
                phone,
                new ESMClass(),
                (byte) 0,
                (byte) 1,
                null,
                null,
                new RegisteredDelivery(SMSCDeliveryReceipt.SUCCESS_FAILURE),
                (byte) 0,
                new GeneralDataCoding(
                        Alphabet.ALPHA_DEFAULT,
                        MessageClass.CLASS1,
                        false
                ),
                (byte) 0,
                message.getBytes(StandardCharsets.UTF_8)
        );
    }

    private void closeSession(SMPPSession session) {
        try {
            if (session != null && session.getSessionState().isBound()) {
                session.unbindAndClose();
            }
        } catch (Exception e) {
            logger.error("Ошибка закрытия сессии: {}", e.getMessage());
        }
    }

    private void handleError(String message, Exception e) {
        logger.error("{}: {}", message, e.getMessage());
        if (logger.isDebugEnabled()) {
            e.printStackTrace();
        }
    }
}
