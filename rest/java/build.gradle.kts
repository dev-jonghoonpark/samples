/*
 * Copyright 2026 UCP Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

plugins {
    java
    id("org.springframework.boot") version "4.1.1"
    id("io.spring.dependency-management") version "1.1.7"
}

description = "UCP merchant server reference implementation (Java, Spring Boot)."

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.xerial:sqlite-jdbc:3.53.4.0")
    // PEM parsing and public-key derivation for WEBHOOK_SIGNING_KEY. Signing
    // and verification themselves use the JDK's built-in providers.
    implementation("org.bouncycastle:bcpkix-jdk18on:1.86")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<JavaCompile>().configureEach {
    // Java 17 is the baseline; any newer JDK can build and run the server.
    options.release = 17
    options.compilerArgs.add("-parameters")
}

tasks.test {
    useJUnitPlatform()
}
