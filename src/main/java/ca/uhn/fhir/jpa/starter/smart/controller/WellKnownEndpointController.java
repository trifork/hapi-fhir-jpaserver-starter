package ca.uhn.fhir.jpa.starter.smart.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;

@RestController
@ConditionalOnProperty(prefix = "hapi.fhir", name = "smart_enabled", havingValue = "true")
public class WellKnownEndpointController {

	@Value("${smart.wellknown.issuer}")
	@SerializedName("issuer")
	public String issuer;

	@Value("${smart.wellknown.jwks_uri}")
	@SerializedName("jwks_uri")
	public String jwksUri;

	@Value("${smart.wellknown.authorization_endpoint}")
	@SerializedName("authorization_endpoint")
	public String authorizationEndpoint;

	@Value("${smart.wellknown.grant_types_supported}")
	@SerializedName("grant_types_supported")
	public String[] grantTypesSupported;

	@Value("${smart.wellknown.token_endpoint}")
	@SerializedName("token_endpoint")
	public String tokenEndpoint;

	@Value("${smart.wellknown.token_endpoint_auth_methods_supported}")
	@SerializedName("token_endpoint_auth_methods_supported")
	public String[] tokenEndpointAuthMethodsSupported;

	@Value("${smart.wellknown.registration_endpoint}")
	@SerializedName("registration_endpoint")
	public String registrationEndpoint;

	@Value("${smart.wellknown.scopes_supported}")
	@SerializedName("scopes_supported")
	public String[] scopesSupported;

	@Value("${smart.wellknown.response_types_supported}")
	@SerializedName("response_types_supported")
	public String[] responseTypesSupported;

	@Value("${smart.wellknown.management_endpoint}")
	@SerializedName("management_endpoint")
	public String managementEndpoint;

	@Value("${smart.wellknown.introspection_endpoint}")
	@SerializedName("introspection_endpoint")
	public String introspectionEndpoint;

	@Value("${smart.wellknown.revocation_endpoint}")
	@SerializedName("revocation_endpoint")
	public String revocationEndpoint;

	@Value("${smart.wellknown.capabilities}")
	@SerializedName("capabilities")
	public String[] capabilities;

	@Value("${smart.wellknown.code_challenge_methods_supported}")
	@SerializedName("code_challenge_methods_supported")
	public String[] codeChallengeMethodsSupported;

	/**
	 * Get request to support well-known endpoints for authorization metadata. See
	 * http://www.hl7.org/fhir/smart-app-launch/conformance/index.html#using-well-known
	 *
	 * @param theRequest Incoming request, unused here
	 * @return String representing json object of metadata returned at this url
	 * @throws JsonProcessingException
	 */
	@GetMapping(path = "/smart-configuration", produces = { "application/json" })
	public String getWellKnownJson(HttpServletRequest theRequest) throws JsonProcessingException {

		return getWellKnownJson();
	}

	public String getWellKnownJson() throws JsonProcessingException {
		return new GsonBuilder().setPrettyPrinting().create().toJson(this);
	}
}
