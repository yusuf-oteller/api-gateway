# API Gateway

This is the **API Gateway** component for the Hotel Reservation Microservices System.

## Technologies

- Spring Boot (Reactive WebFlux)
- Spring Cloud Gateway
- Redis (Rate Limiting)
- JWT Authentication
- Docker + Docker Compose
- WebTestClient (for Integration Tests)

---

## Features

- JWT-based Authentication using a custom Gateway filter
- IP-based Rate Limiting via Redis
- Path-based routing for microservices
- Centralized security rules
- Integration Tests with real port and stubbed controllers

---

## ntegration Tests

Test class: `ApiGatewayIntegrationTest.java`

Tests:

- Valid JWT routing
- Rate limiting
- Health check endpoint

---

## Routes Configured

| Path Prefix                | Service              | Auth Required |
|----------------------------|----------------------|----|
| `/api/v1/auth/**`          | Auth Service         | No |
| `/api/v1/hotels/**`        | Hotel Service        | Yes |
| `/api/v1/rooms/**`         | Hotel Service        | Yes |
| `/api/v1/reservations/**`  | Reservation Service  | Yes |
| `/api/v1/notifications/**` | Notification Service | Yes |
| `/api/v1/payments/**`      | Payment Service      | Yes |
| `/actuator/**`             | Gateway Itself       | No |

---

## JWT Filter

A custom `JwtAuthFilter` verifies the token, extracts claims (`sub`, `email`, `role`) and injects them into headers:

```http
X-User-Id: <userId>
X-User-Email: <email>
X-User-Role: <role>
```

---

## Rate Limiting

- Redis-based
- IP Resolver (`RemoteAddress`)
- Configurable `replenishRate` and `burstCapacity` per route

---

## Run the Gateway

```bash
./mvnw spring-boot:run
```

or via Docker:

```bash
docker-compose up --build
```

---

## Run Tests

```bash
./mvnw test
```

---

## Developer Notes

- You can override security in test using a `@TestConfiguration` that provides a custom `SecurityWebFilterChain`.
- Stub controllers (like `HotelController`) can be injected only during test via `@SpringBootTest(classes = {...})`.

