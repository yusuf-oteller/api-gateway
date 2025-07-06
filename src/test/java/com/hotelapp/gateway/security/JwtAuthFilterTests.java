package com.hotelapp.gateway.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;

import javax.crypto.SecretKey;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.util.Base64;
import java.util.Date;

@WebFluxTest
@Import({JwtAuthFilter.class})
public class JwtAuthFilterTests {

    @MockitoBean
    private RouteLocator routeLocator;

    @Value("${jwt.secret}")
    private String secret;

    private WebTestClient webTestClient;

    @BeforeEach
    public void setUp(WebTestClient.Builder builder) {
        this.webTestClient = builder.baseUrl("http://localhost:8080").build();
    }

    private String createJwt(String userId, String role, String secretKey) {
        SecretKey key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(secretKey));
        return Jwts.builder()
                .setSubject(userId)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    @Test
    public void testUnauthorizedRequest() {
        webTestClient.get().uri("/api/v1/hotels")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    public void testValidTokenRequest() {
        String token = createJwt("123", "USER", "ZhV3+eY767wZQ4ce+qb8PbwanES3wA8XpBvAkC2ZiVA=");
        webTestClient.get().uri("/api/v1/hotels")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isOk();
    }
}
