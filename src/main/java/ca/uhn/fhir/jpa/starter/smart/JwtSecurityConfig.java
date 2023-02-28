package ca.uhn.fhir.jpa.starter.smart;

import ca.uhn.fhir.jpa.starter.smart.util.OAuth2JWTConditional;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Conditional(OAuth2JWTConditional.class)
@Configuration
@EnableWebSecurity
public class JwtSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().anyRequest().permitAll().and().csrf().disable();
	}

	@Bean
	JwtDecoder jwtDecoder(OAuth2ResourceServerProperties properties) {
		OAuth2ResourceServerProperties.Jwt jwtConfiguration = properties.getJwt();
		return NimbusJwtDecoder.withJwkSetUri(jwtConfiguration.getJwkSetUri()).build();
	}

}
