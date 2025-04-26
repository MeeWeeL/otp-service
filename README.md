# API Documentation

## Регистрация

### URL
```
POST http://localhost:8080/auth/register
```

### Headers
```
Content-Type: application/json
```

### Body
```json
{
    "login": "testuser",
    "password": "password123",
    "role": "USER"
}
```

### Ответ
```json
{
    "id": 1,
    "login": "testuser",
    "password": "$2a$10$S.U1BH02CwIzmTBjGr6Sy.ctbPuPd8qLPtWI4KPEeelYm.F6LzauG",
    "role": "USER",
    "enabled": true,
    "username": "testuser",
    "authorities": [
        {
            "authority": "ROLE_USER"
        }
    ],
    "credentialsNonExpired": true,
    "accountNonExpired": true,
    "accountNonLocked": true
}
```

---

## Авторизация

### URL
```
POST http://localhost:8080/auth/login
```

### Headers
```
Content-Type: application/json
```

### Body
```json
{
    "login": "testuser",
    "password": "password123"
}
```

### Ответ
```json
{
    "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0dXNlciIsImlhdCI6MTc0NTcwNDk1NSwiZXhwIjoxNzQ1NzA4NTU1fQ.207fAtKu0-Kmn32S5Hi37fvHNZD7EIu4Eza3l6Ssy0o"
}
```

---

## Отправка OTP подтверждения

### URL
```
POST http://localhost:8080/api/otp/generate
```

### Headers
```
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0dXNlciIsImlhdCI6MTc0NTcwNDk1NSwiZXhwIjoxNzQ1NzA4NTU1fQ.207fAtKu0-Kmn32S5Hi37fvHNZD7EIu4Eza3l6Ssy0o
```

### Body
```json
{
    "destination": "1394512149",
    "channel": "TELEGRAM", // Или другой сервис
    "operationId": "12341"
}
```

### Ответ
```
Code sent via TELEGRAM
```

![image](https://github.com/user-attachments/assets/61d60baa-daac-40ae-a449-5f77cbf65a6d)

---
