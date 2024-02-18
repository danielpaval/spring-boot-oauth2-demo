package com.example.oauth2.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
        String idToken = ((DefaultOidcUser) oAuth2AuthenticationToken.getPrincipal()).getIdToken().getTokenValue();
        OAuth2AuthorizedClient oAuth2AuthorizedClient = getOAuth2AuthorizedClient(oAuth2AuthenticationToken);
        String accessToken = oAuth2AuthorizedClient.getAccessToken().getTokenValue();
        String refreshToken = oAuth2AuthorizedClient.getRefreshToken().getTokenValue();
        response.setStatus(HttpServletResponse.SC_OK);
        response.addCookie(createCookie(ApplicationConstants.ACCESS_TOKEN_LABEL, accessToken, false));
        URL requestUrl = new URL(request.getRequestURL().toString());
        redirectStrategy.sendRedirect(
                request,
                response,
                requestUrl.getPort() > 0 ?
                        "%s://%s:%d/account?idToken=%s&refreshToken=%s".formatted(
                                getActualProtocol(request),
                                requestUrl.getHost(),
                                requestUrl.getPort(),
                                idToken,
                                refreshToken
                        ) :
                        "%s://%s/account?idToken=%s&refreshToken=%s".formatted(
                                getActualProtocol(request),
                                requestUrl.getHost(),
                                idToken,
                                refreshToken
                        )
        );
    }

    private OAuth2AuthorizedClient getOAuth2AuthorizedClient(OAuth2AuthenticationToken oauthToken) {
        return
                oAuth2AuthorizedClientService.loadAuthorizedClient(
                        oauthToken.getAuthorizedClientRegistrationId(),
                        oauthToken.getName());
    }

    private String getActualProtocol(HttpServletRequest request) {
        String forwardedProtocol = request.getHeader("X-Forwarded-Proto");
        return forwardedProtocol != null ? forwardedProtocol : request.isSecure() ? "https" : "http";
    }

    private Cookie createCookie(String name, String value) {
        return createCookie(name, value, true);
    }

    private Cookie createCookie(String name, String value, boolean httpOnly) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(httpOnly);
        cookie.setSecure(true);
        cookie.setPath("/");
        return cookie;
    }

}
