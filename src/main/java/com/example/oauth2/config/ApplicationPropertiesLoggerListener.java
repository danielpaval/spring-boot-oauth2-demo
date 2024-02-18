package com.example.oauth2.config;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationEnvironmentPreparedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * {@link ApplicationListener} to log all application properties
 */
@Slf4j
@Component
public class ApplicationPropertiesLoggerListener implements ApplicationListener<ApplicationEnvironmentPreparedEvent> {

    private static final List<String> PASSWORD_PROPERTY_NAMES = List.of(
            "spring.security.oauth2.client.registration.keycloak-private.client-secret"
    );

    private ConfigurableEnvironment environment;

    private boolean isFirstRun = true;

    @Override
    public void onApplicationEvent(ApplicationEnvironmentPreparedEvent event) {
        if (isFirstRun) {
            environment = event.getEnvironment();
            logAllProperties();
        }
        isFirstRun = false;
    }

    private void logAllProperties() {
        for (EnumerablePropertySource<?> enumerablePropertySource : findAllEnumerablePropertySources()) {
            if (enumerablePropertySource.getName().matches(".*application.*\\.(yml|properties).*")) {
                logEnumerablePropertySourceProperties(enumerablePropertySource);
            }
        }
    }

    private void logEnumerablePropertySourceProperties(EnumerablePropertySource<?> enumerablePropertySource) {
        log.info("{} properties:", enumerablePropertySource.getName());
        String[] propertyNames = enumerablePropertySource.getPropertyNames();
        Arrays.sort(propertyNames);
        for (String propertyName : propertyNames) {
            String resolvedPropertyValue = environment.getProperty(propertyName);
            String sourcePropertyValue = enumerablePropertySource.getProperty(propertyName).toString();
            if (resolvedPropertyValue.equals(sourcePropertyValue)) {
                if (isPasswordPropertyName(propertyName)) {
                    log.info("[{}] = [{}]", propertyName, maskPassword(resolvedPropertyValue));
                } else {
                    log.info("[{}] = [{}]", propertyName, resolvedPropertyValue);
                }
            } else {
                if (isPasswordPropertyName(propertyName)) {
                    log.info(
                            "[{}] = [{}] OVERRIDDEN to [{}]",
                            propertyName,
                            maskPassword(sourcePropertyValue),
                            maskPassword(resolvedPropertyValue)
                    );
                } else {
                    log.info("[{}] = [{}] OVERRIDDEN to [{}]", propertyName, sourcePropertyValue, resolvedPropertyValue);
                }
            }
        }
    }

    private List<EnumerablePropertySource<?>> findAllEnumerablePropertySources() {
        List<EnumerablePropertySource<?>> enumerablePropertySources = new LinkedList<>();
        for (PropertySource<?> propertySource : environment.getPropertySources()) {
            if (propertySource instanceof EnumerablePropertySource) {
                enumerablePropertySources.add((EnumerablePropertySource<?>) propertySource);
            }
        }
        return enumerablePropertySources;
    }

    private boolean isPasswordPropertyName(String propertyName) {
        return PASSWORD_PROPERTY_NAMES.contains(propertyName);
    }

    private static String maskPassword(String password) {
        return maskPassword(password, password != null ? password.length() / 2 : 0); // Show / hide half
    }

    private static String maskPassword(String password, int unmaskedLength) {
        if (password != null && password.length() > unmaskedLength) {
            return password.substring(0, unmaskedLength) + "*".repeat(password.length() - unmaskedLength);
        }
        return password;
    }

}
