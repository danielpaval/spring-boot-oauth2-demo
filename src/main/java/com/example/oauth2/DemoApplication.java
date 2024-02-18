package com.example.oauth2;

import com.example.oauth2.config.ApplicationPropertiesLoggerListener;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

@SpringBootApplication
@EnableConfigurationProperties({
		OAuth2ResourceServerProperties.class
})
@EnableAspectJAutoProxy
@EnableFeignClients
public class DemoApplication {

	public static void main(String[] args) {
		new SpringApplicationBuilder(DemoApplication.class)
				.listeners(new ApplicationPropertiesLoggerListener())
				.run(args);
	}

}
