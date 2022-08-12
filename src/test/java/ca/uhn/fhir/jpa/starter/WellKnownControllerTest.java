package ca.uhn.fhir.jpa.starter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestTemplate;

import static org.junit.jupiter.api.Assertions.*;


@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = Application.class)
@ActiveProfiles("smart")
class WellKnownControllerTest {

	private static final org.slf4j.Logger ourLog = org.slf4j.LoggerFactory.getLogger(WellKnownControllerTest.class);

	@LocalServerPort
	private int port;
	private String ourServerBase;

	@Value("${smart.wellknown.authorization_endpoint}")
	public String authorizationEndpoint;

	@BeforeEach
	void setUp() {
		ourServerBase = "http://localhost:" + port + "/fhir/";

	}

	@Test
	void testWellKnown() {
		// ARRANGE
		RestTemplate restTemplate = new RestTemplate();

		// ACT
		ResponseEntity<String> response = restTemplate
				.getForEntity(ourServerBase + "/.well-known/smart-configuration", String.class);

		ourLog.info("response.getBody()->\n{}", response.getBody());
		assertTrue(response.getBody().contains("launch-standalone"));
		// ASSERT
		assertEquals(HttpStatus.OK, response.getStatusCode());
	}

	@Test
	void testCapabilityStmt() {
		// ARRANGE
		RestTemplate restTemplate = new RestTemplate();

		// ACT
		ResponseEntity<String> response = restTemplate.getForEntity(ourServerBase + "/metadata", String.class);

		ourLog.info("response.getBody()->\n{}", response.getBody());
		assertTrue(response.getBody().contains(authorizationEndpoint));
		// ASSERT
		assertEquals(HttpStatus.OK, response.getStatusCode());
	}
}
