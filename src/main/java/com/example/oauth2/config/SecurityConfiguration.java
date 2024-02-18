package com.example.oauth2.config;

import com.example.oauth2.util.AuthenticationTokenUtils;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSAlgorithmFamilyJWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.DelegatingJwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.util.Collection;

@Slf4j
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
@RequiredArgsConstructor
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final OAuth2ResourceServerProperties oAuth2ResourceServerProperties;

    private final ClientRegistrationRepository clientRegistrationRepository;

    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

    private final Converter<Jwt, Collection<GrantedAuthority>> grantedAuthoritiesConverter;

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.debug(true);
        web.ignoring()
                .antMatchers(HttpMethod.OPTIONS, "/**")
                .antMatchers("/", "/account", "/token", "/login/tenants")
                .antMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html")
                .antMatchers("/webjars/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .headers(configurer -> configurer.frameOptions().disable())
                .cors(Customizer.withDefaults())
                .sessionManagement(configurer -> configurer
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeRequests(registry -> registry
                        .antMatchers("/", "/favicon.ico", "/error").permitAll()
                        .antMatchers("/login/oauth2/code/*").permitAll()
                        .antMatchers("/oauth2/logout").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(configurer -> configurer
                        .successHandler(oAuth2AuthenticationSuccessHandler)
                )
                .logout(configurer -> configurer
                        .deleteCookies(ApplicationConstants.ACCESS_TOKEN_LABEL)
                        .logoutSuccessHandler(logoutSuccessHandler())
                )
                .oauth2ResourceServer(configurer -> configurer
                        .jwt(jwtConfigurer -> jwtConfigurer
                                .decoder(jwtDecoder())
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                        )
                        .bearerTokenResolver(AuthenticationTokenUtils::readAuthCookie)
                );
    }

    @Bean
    public Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(
                new DelegatingJwtGrantedAuthoritiesConverter(new JwtGrantedAuthoritiesConverter(), grantedAuthoritiesConverter)
        );
        return jwtAuthenticationConverter;
    }

    /**
     * Convenient holder bean for authorization server configuration by issuer URI
     */
    @Bean
    @SneakyThrows
    public OIDCProviderMetadata oidcProviderMetadata() {
        return OIDCProviderMetadata.resolve(new Issuer(oAuth2ResourceServerProperties.getJwt().getIssuerUri()));
    }

    /**
     * Override {@link JwtDecoder} in spring-boot-starter-oauth2-resource-server configuration to handle at+JWT access token header typ
     */
    @Bean
    @SneakyThrows
    public JwtDecoder jwtDecoder() {
        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSTypeVerifier(
                new DefaultJOSEObjectTypeVerifier<>(
                        JOSEObjectType.JWT,
                        new JOSEObjectType("at+JWT")
                )
        );
        jwtProcessor.setJWSKeySelector(
                JWSAlgorithmFamilyJWSKeySelector.fromJWKSetURL(oidcProviderMetadata().getJWKSetURI().toURL())
        );
        return new NimbusJwtDecoder(jwtProcessor);
    }

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        OidcClientInitiatedLogoutSuccessHandler logoutSuccessHandler =
                new OidcClientInitiatedLogoutSuccessHandler(
                        this.clientRegistrationRepository
                );
        logoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");
        return logoutSuccessHandler;
    }

    @Bean
    public OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager(OAuth2AuthorizedClientService oAuth2AuthorizedClientService, ClientRegistrationRepository clientRegistrationRepository) {
        return new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository, oAuth2AuthorizedClientService);
    }

}
