package com.example.oauth2.controller;

import com.example.oauth2.config.ApplicationConstants;
import com.example.oauth2.controller.dto.GreetingRequest;
import com.example.oauth2.controller.dto.GreetingResponse;
import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@PreAuthorize("hasRole('GREETER') or hasAuthority('SCOPE_greeting:greet')")
public class GreetingController {

    @Hidden
    @GetMapping(value = "/greet", produces = MediaType.APPLICATION_JSON_VALUE)
    GreetingResponse inlineGreet(GreetingRequest request) {
        return GreetingResponse.builder()
                .greeting(ApplicationConstants.DEFAULT_GREETING_FORMAT.formatted(request.getName()))
                .build();
    }

    @SecurityRequirement(name = "JWT")
    @SecurityRequirement(name = "OAUTH")
    @PostMapping(value = "/greet", produces = MediaType.APPLICATION_JSON_VALUE)
    GreetingResponse greet(@RequestBody GreetingRequest request) {
        return GreetingResponse.builder()
                .greeting(ApplicationConstants.DEFAULT_GREETING_FORMAT.formatted(request.getName()))
                .build();
    }

}
