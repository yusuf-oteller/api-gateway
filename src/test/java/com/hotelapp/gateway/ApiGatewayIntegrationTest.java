package com.hotelapp.gateway;

import com.hotelapp.gateway.config.TestSecurityConfig;
import com.hotelapp.gateway.teststub.HotelController;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
        classes = {
                ApiGatewayApplication.class,
                HotelController.class
        }
)
@Import(TestSecurityConfig.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ActiveProfiles("test")
public class ApiGatewayIntegrationTest {

    @LocalServerPort
    private int port;

    @Value("${jwt.secret}")
    private String jwtSecret;

    private WebTestClient webTestClient;

    @BeforeEach
    void setup() {
        this.webTestClient = WebTestClient.bindToServer()
                .baseUrl("http://localhost:" + 8089)
                .build();
    }

    private String createJwt(String userId, String email, String role) {
        SecretKey key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(jwtSecret));
        return Jwts.builder()
                .subject(userId)
                .claim("email", email)
                .claim("role", role)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 86400000))
                .signWith(key)
                .compact();
    }

    @Test
    void testValidTokenGatewayRouting() {
        String token = createJwt("1", "admin@example.com", "ADMIN");

        webTestClient.get()
                .uri("/api/v1/hotels")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Content-Type", "application/json")
                .expectBody().jsonPath("$.message").isEqualTo("Hotel data");
    }

    @Test
    void testRateLimiting() {
        String token = createJwt("1", "admin@example.com", "ADMIN");

        for (int i = 0; i < 3; i++) {
            webTestClient.get()
                    .uri("/api/v1/hotels")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .exchange();
        }

        webTestClient.get()
                .uri("/api/v1/hotels")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }

    @Test
    void testHealthEndpoint() {
        webTestClient.get()
                .uri("/actuator/health")
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.status").isEqualTo("UP");
    }
}
