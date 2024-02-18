package com.example.oauth2.controller;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import io.swagger.v3.oas.annotations.Hidden;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Controller
@RequiredArgsConstructor
public class AccountController {

    private final OIDCProviderMetadata oidcProviderMetadata;

    private final ClientRegistrationRepository clientRegistrationRepository;

    @GetMapping
    public String home() {
        return "index";
    }

    @Hidden
    @GetMapping("/account")
    public String account(Model model) {
        model.addAttribute("tokenEndpointUrl", oidcProviderMetadata.getTokenEndpointURI());
        model.addAttribute("userInfoEndpointUrl", oidcProviderMetadata.getUserInfoEndpointURI());
        model.addAttribute("clientRegistrations", getClientRegistrations());
        return "account";
    }

    @Hidden
    @GetMapping("/account/context")
    @ResponseBody
    public Map<String, Object> context(Authentication authentication) {
        Map<String, Object> context = new HashMap<>();
        if (authentication != null) {
            context.put("authorities", authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
            if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
                context.put("companyIds", jwtAuthenticationToken.getToken().getClaim("company_ids"));
            }
        }
        return context;
    }

    private List<ClientRegistration> getClientRegistrations() {
        InMemoryClientRegistrationRepository inMemoryClientRegistrationRepository = (InMemoryClientRegistrationRepository) clientRegistrationRepository;
        List<ClientRegistration> clientRegistrations = new ArrayList<>();
        inMemoryClientRegistrationRepository.iterator().forEachRemaining(clientRegistrations::add);
        return clientRegistrations;
    }

}
