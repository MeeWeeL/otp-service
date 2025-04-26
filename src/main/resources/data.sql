INSERT INTO otp_config (id, code_length, expiration_time_minutes)
VALUES (1, 6, 5)
ON CONFLICT (id) DO NOTHING;
