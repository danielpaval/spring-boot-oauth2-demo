package com.example.oauth2.util;

import com.example.oauth2.config.ApplicationConstants;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Optional;

public class AuthenticationTokenUtils {

    public static String readAuthCookie(HttpServletRequest request) {
        return readCookieValue(request, ApplicationConstants.ACCESS_TOKEN_LABEL).orElse(null);
    }

    private static Optional<String> readCookieValue(HttpServletRequest request, String cookieName) {
        if (request.getCookies() != null) {
            return Arrays.stream(request.getCookies())
                    .filter(cookie -> cookieName.equals(cookie.getName()))
                    .map(Cookie::getValue)
                    .findAny();
        }
        return Optional.empty();
    }

}
