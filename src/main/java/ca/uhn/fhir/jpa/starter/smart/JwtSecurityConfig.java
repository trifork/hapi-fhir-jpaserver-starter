package ca.uhn.fhir.jpa.starter.smart;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

//@Conditional(OAuth2JWTConditional.class)
@ConditionalOnProperty(prefix = "hapi.fhir", name = "smart_enabled", havingValue = "true")
@Configuration
@EnableWebSecurity
public class JwtSecurityConfig {

	@Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
  private String jwkSetUri;

	@Bean
	public JwtDecoder jwtDecoder() {
		return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
	}
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		return http.authorizeRequests()
				.anyRequest()
				.permitAll()
				.and()
				.csrf().disable()
				.build();	
	}
}
