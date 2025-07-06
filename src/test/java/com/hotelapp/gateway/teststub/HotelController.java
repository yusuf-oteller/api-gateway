package com.hotelapp.gateway.teststub;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.MediaType;
import java.util.Map;
import java.util.HashMap;

@RestController
@RequestMapping("/api/v1/hotels")
public class HotelController {

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, String>> getHotels() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "Hotel data");

        return ResponseEntity.ok().body(response);
    }
}