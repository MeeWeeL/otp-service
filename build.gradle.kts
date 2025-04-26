plugins {
    java
    application
    id("org.springframework.boot") version "3.2.4"
    id("io.spring.dependency-management") version "1.1.4"
    kotlin("jvm") version "1.9.23"
}

group = "com.example"
version = "1.0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
}

dependencies {
    // Spring
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-mail")
    implementation("org.springframework.boot:spring-boot-starter")
    implementation("org.springframework.boot:spring-boot-starter-logging")

    // Database
    runtimeOnly("org.postgresql:postgresql")

    // JWT
    implementation("io.jsonwebtoken:jjwt-api:0.12.5")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.5")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.5")

    // Email
    implementation("com.sun.mail:javax.mail:1.6.2")

    // SMS
    implementation("org.opensmpp:opensmpp-core:3.0.0")

    // Для SMPP v3.4 и выше
    implementation("org.jsmpp:jsmpp:3.0.0")

    // Telegram
    implementation("org.apache.httpcomponents:httpclient:4.5.14")

    // Для работы с файлами
    implementation("commons-io:commons-io:2.16.1")

    // Lombok
    compileOnly("org.projectlombok:lombok:1.18.32")
    annotationProcessor("org.projectlombok:lombok:1.18.32")
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
}
