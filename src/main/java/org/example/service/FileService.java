package org.example.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;

@Service
public class FileService {
    private static final Logger logger = LoggerFactory.getLogger(FileService.class);

    @Value("${otp.file.path:otp_codes.txt}")
    private String filePath;

    public void saveCodeToFile(String code) {
        try {
            Path path = Paths.get(filePath);
            String content = String.format(
                    "[%s] Код: %s\n",
                    LocalDateTime.now(),
                    code
            );

            Files.writeString(
                    path,
                    content,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND
            );

            logger.info("Код сохранен в файл: {}", path.toAbsolutePath());
        } catch (IOException e) {
            logger.error("Ошибка записи в файл: {}", e.getMessage());
            throw new RuntimeException("File write error", e);
        }
    }
}
