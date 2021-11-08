package ca.uhn.fhir.jpa.starter.smart.util;

import org.jetbrains.annotations.NotNull;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.AbstractEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.type.AnnotatedTypeMetadata;

public class OAuth2JWTConditional implements Condition {

	@Override
	public boolean matches(ConditionContext context, @NotNull AnnotatedTypeMetadata metadata) {

		AbstractEnvironment env = (AbstractEnvironment) context.getEnvironment();
		for (org.springframework.core.env.PropertySource<?> source : env.getPropertySources()) {
			if (source instanceof MapPropertySource) {
				for (String propertyName : ((MapPropertySource) source).getSource().keySet()) {
					if (propertyName.startsWith("spring.security.oauth2.resourceserver.jwt")) {
						return true;
					}
				}
			}
		}
		return false;
	}
}
