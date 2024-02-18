package com.example.oauth2.config;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component
@Profile("custom")
@RequiredArgsConstructor
public class CustomUserInfoRolesGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final OIDCProviderMetadata oidcProviderMetadata;

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        try {
            Instant start = Instant.now();
            HTTPResponse httpResponse = new UserInfoRequest(oidcProviderMetadata.getUserInfoEndpointURI(), new BearerAccessToken(jwt.getTokenValue()))
                    .toHTTPRequest()
                    .send();
            Duration duration = Duration.between(start, Instant.now());
            UserInfoResponse userInfoResponse = UserInfoResponse.parse(httpResponse);
            if (userInfoResponse.indicatesSuccess()) {
                UserInfo userInfo = userInfoResponse.toSuccessResponse().getUserInfo();
                List<String> roles = Optional.ofNullable(userInfo.getStringListClaim("roles")).orElse(Collections.emptyList()).stream()
                        .map(roleName -> "ROLE_" + roleName)
                        .collect(Collectors.toList());
                log.info("Retrieved custom roles (user info): {} ({})", roles, duration);
                grantedAuthorities.addAll(roles.stream().map(SimpleGrantedAuthority::new).toList());
            } else {
                log.warn("Could not retrieve custom roles (user info): {} ({})", userInfoResponse.toErrorResponse().getErrorObject().toString(), duration);
            }
        } catch (Exception e) {
            log.warn("Could not retrieve custom roles (user info): {}", e.getMessage());
        }
        return grantedAuthorities;
    }

}
