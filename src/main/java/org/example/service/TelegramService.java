package org.example.service;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Service
public class TelegramService {
    private static final Logger logger = LoggerFactory.getLogger(TelegramService.class);

    @Value("${telegram.bot.token}")
    private String botToken;

    @Value("${telegram.chat.id}")
    private String chatId;

    public void sendCode(String destination, String code) {
        String targetChatId = (destination != null && !destination.isEmpty())
                ? destination
                : chatId;

        String messageText = String.format("Ваш код подтверждения: %s", code);
        String encodedMessage = URLEncoder.encode(messageText, StandardCharsets.UTF_8);

        String url = String.format(
                "https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s",
                botToken,
                targetChatId,
                encodedMessage
        );

        sendRequest(url);
    }

    private void sendRequest(String url) {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url);
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                int statusCode = response.getStatusLine().getStatusCode();
                if (statusCode != 200) {
                    logger.error("Ошибка отправки в Telegram. Код: {}", statusCode);
                } else {
                    logger.info("Сообщение отправлено в Telegram");
                }
            }
        } catch (IOException e) {
            logger.error("Ошибка соединения с Telegram: {}", e.getMessage());
        }
    }
}
