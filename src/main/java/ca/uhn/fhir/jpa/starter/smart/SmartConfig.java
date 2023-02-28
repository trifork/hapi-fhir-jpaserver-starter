package ca.uhn.fhir.jpa.starter.smart;

import ca.uhn.fhir.jpa.starter.smart.controller.WellKnownEndpointController;
import ca.uhn.fhir.jpa.starter.smart.security.builder.CompartmentAuthorizationRuleBuilder;
import ca.uhn.fhir.jpa.starter.smart.util.SmartResourceMapping;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.DispatcherServlet;

@Configuration
@ConditionalOnProperty(prefix = "hapi.fhir", name = "smart_enabled", havingValue = "true")
public class SmartConfig  {
	
	@Value("${hapi.fhir.fhir_servlet_wellknown_url_mapping:/fhir/.well-known/*}")
	String wellKnownServletUrlMapping;
	
	@Value("${smart.wellknown.authorization_endpoint}")
	public String authorizationEndpoint;

	@Value("${smart.wellknown.token_endpoint}")
	public String tokenEndpoint;

	@Value("${smart.wellknown.management_endpoint}")
	public String managementEndpoint;

	@Value("${smart.wellknown.introspection_endpoint}")
	public String introspectionEndpoint;

	@Value("${smart.wellknown.revocation_endpoint}")
	public String revocationEndpoint;
	
	@Bean
	CompartmentAuthorizationRuleBuilder compartmentAuthorizationRuleBuilder() {
		CompartmentAuthorizationRuleBuilder builder = new CompartmentAuthorizationRuleBuilder() ;
		builder.registerResource("patient", new SmartResourceMapping("Patient", "patient"));
		builder.registerResource("user", new SmartResourceMapping("Practitioner", "user"));
		return builder;
	}
	
	@Bean
	public ServletRegistrationBean wellknownRegistrationBean() {

		AnnotationConfigWebApplicationContext annotationConfigWebApplicationContext = new AnnotationConfigWebApplicationContext();
		DispatcherServlet dispatcherServlet = new DispatcherServlet(
				annotationConfigWebApplicationContext);
		dispatcherServlet.setContextClass(AnnotationConfigWebApplicationContext.class);
		dispatcherServlet.setContextConfigLocation(WellKnownEndpointController.class.getName());

		ServletRegistrationBean registrationBean = new ServletRegistrationBean();
		registrationBean.setName("wellknown");
		registrationBean.setServlet(dispatcherServlet);
		registrationBean.addUrlMappings(wellKnownServletUrlMapping);
		registrationBean.setLoadOnStartup(1);
		return registrationBean;
	}
	
	@Bean
	SmartCapabilityStatementInterceptorR4 smartCapabilityStatementInterceptorR4() {
		SmartCapabilityStatementInterceptorR4 interceptor = new SmartCapabilityStatementInterceptorR4(authorizationEndpoint, tokenEndpoint, managementEndpoint, introspectionEndpoint, revocationEndpoint);
		return interceptor;
	}
}
