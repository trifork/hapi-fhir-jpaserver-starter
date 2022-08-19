package ca.uhn.fhir.jpa.starter;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.jpa.api.dao.IFhirResourceDao;
import ca.uhn.fhir.rest.api.MethodOutcome;
import ca.uhn.fhir.rest.client.api.IGenericClient;
import ca.uhn.fhir.rest.client.api.ServerValidationModeEnum;
import ca.uhn.fhir.rest.gclient.*;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import ca.uhn.fhir.rest.server.exceptions.ForbiddenOperationException;
import org.hl7.fhir.instance.model.api.IBaseBundle;
import org.hl7.fhir.instance.model.api.IBaseResource;
import org.hl7.fhir.r4.model.*;
import org.hl7.fhir.r4.model.Bundle.BundleEntryComponent;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;


@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = Application.class)
@ActiveProfiles("smart")
class AuthorizationInterceptorTest {

	private static final org.slf4j.Logger ourLog = org.slf4j.LoggerFactory.getLogger(AuthorizationInterceptorTest.class);

	/**
	 * <h1>BEWARE</h1>
	 *
	 * The test will fail if the boot maven profile is disabled so make sure they're run with said profile.
	 */
	public static final String ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE = "HTTP 403 : HAPI-0333: Access denied by rule: Deny all requests that do not match any pre-defined rules";
	public static final String ACCESS_DENIED_BY_RULE_DENY_ALL_REQUESTS_IF_NO_ID_EXCEPTION_MESSAGE = "HTTP 403 : HAPI-0333: Access denied by rule: Deny ALL patient requests if no launch context is given!";
	private IGenericClient client;
	private FhirContext ctx;

	@MockBean
	private JwtDecoder mockJwtDecoder;

	@Autowired
	private IFhirResourceDao<Patient> patientResourceDao;

	@Autowired
	private IFhirResourceDao<Endpoint> endpointResourceDao;

	@Autowired
	private IFhirResourceDao<Observation> observationResourceDao;

	@Autowired 
	private IFhirResourceDao<Practitioner> practitionerResourceDao;

	@Autowired
	private IFhirResourceDao<Organization> organizationResourceDao;

	@Autowired
	private IFhirResourceDao<Group> groupResourceDao;

	@LocalServerPort
	private int port;

	@Value("${hapi.fhir.smart_admin_group_claim}")
	private String smartAdminGroupClaim;

	private static final String MOCK_JWT = "FAKE_TOKEN";
	private static final String MOCK_HEADER = "Bearer " + MOCK_JWT;

	@BeforeEach
	void setUp() {
		ctx = FhirContext.forR4();
		ctx.getRestfulClientFactory().setServerValidationMode(ServerValidationModeEnum.NEVER);
		ctx.getRestfulClientFactory().setSocketTimeout(1200 * 1000);
		String ourServerBase = "http://localhost:" + port + "/fhir/";
		client = ctx.newRestfulGenericClient(ourServerBase);

		Properties props = new Properties();
		props.put("spring.autoconfigure.exclude", "org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration");
	}

	@Test
	void testBuildRules_readMetadata_noJwtTokenProvided() {
		// ARRANGE
		RestTemplate restTemplate = new RestTemplate();

		// ACT
		ResponseEntity<String> response = restTemplate.getForEntity("http://localhost:"+port+"/fhir/metadata",  String.class);

		// ASSERT
		assertEquals(HttpStatus.OK, response.getStatusCode());
	}

	@Test
	void testBuildRules_readPatient_noJwtTokenProvided() {
		// ACT
		IReadExecutable<IBaseResource> patientReadExecutable = client.read().resource("Patient").withId("123");
		AuthenticationException authenticationException = assertThrows(AuthenticationException.class, patientReadExecutable::execute);

		// ASSERT
		assertEquals("HTTP 401 : Token is required when performing a narrowing search operation", authenticationException.getMessage());
	}

	@Test
	void testBuildRules_readPatient_jwtTokenContainsOnlyWriteScope() {
		// ARRANGE
		String mockId = "123";

		HashMap<String, Object> claims = new HashMap<>();
		claims.put("scope", "patient/*.write");
		claims.put("patient", mockId);

		mockJwtWithClaims(claims);
		// ACT
		IReadExecutable<IBaseResource> patientReadExecutable = client.read().resource("Patient").withId(mockId).withAdditionalHeader("Authorization", MOCK_HEADER);
		ForbiddenOperationException forbiddenOperationException = assertThrows(ForbiddenOperationException.class, patientReadExecutable::execute);

		// ASSERT
		assertEquals("HTTP 403 : Read scope is required when performing a narrowing search operation", forbiddenOperationException.getMessage());
	}

	@Test
	void testBuildRules_readPatient_jwtTokenOnlyContainsSpecificResourcePermissions() {
		// ARRANGE
		String mockId = "123";

		HashMap<String, Object> claims = new HashMap<>();
		claims.put("scope", "patient/Observation.*");
		claims.put("patient", mockId);

		mockJwtWithClaims(claims);
		// ACT
		IReadExecutable<IBaseResource> patientReadExecutable = client.read().resource("Patient").withId(mockId).withAdditionalHeader("Authorization", MOCK_HEADER);
		ForbiddenOperationException forbiddenOperationException = assertThrows(ForbiddenOperationException.class, patientReadExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@Test
	void testBuildRules_readPatient_unmappedCompartment() {
		// ARRANGE
		String mockId = "123";
		HashMap<String, Object> claims = new HashMap<>();
		claims.put("scope", "random/*.*");
		mockJwtWithClaims(claims);

		// ACT
		IReadExecutable<IBaseResource> patientReadExecutable = client.read().resource("Patient").withId(mockId).withAdditionalHeader("Authorization", MOCK_HEADER);
		ForbiddenOperationException forbiddenOperationException = assertThrows(ForbiddenOperationException.class, patientReadExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource("getReadPatientClinicalScopes")
	void testBuildRules_readPatient_jwtTokenContainsReadScopesButNotPatientId(Map<String, Object> claims) {
		// ARRANGE
		String mockId = "123";
		mockJwtWithClaims(claims);

		// ACT
		IReadExecutable<IBaseResource> patientReadExecutable = client.read().resource("Patient").withId(mockId).withAdditionalHeader("Authorization", MOCK_HEADER);
		ForbiddenOperationException forbiddenOperationException = assertThrows(ForbiddenOperationException.class, patientReadExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_BY_RULE_DENY_ALL_REQUESTS_IF_NO_ID_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource("getReadPatientClinicalScopes")
	void testBuildRules_readPatient_providedJwtContainsReadScopesAndPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		String mockId = mockPatient.getIdElement().getIdPart();

		claims.put("patient", mockId);

		mockJwtWithClaims(claims);
		// ACT
		IReadExecutable<IBaseResource> patientReadExecutable = client.read().resource("Patient").withId(mockId).withAdditionalHeader("Authorization", MOCK_HEADER);
		IBaseResource patient = patientReadExecutable.execute();

		// ASSERT
		assertEquals(mockPatient.getIdElement().getIdPart(), patient.getIdElement().getIdPart());
	}

	@ParameterizedTest
	@MethodSource("getReadPatientClinicalScopes")
	void testBuildRules_readPatient_providedJwtContainsReadScopesButWrongPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		String mockId = mockPatient.getIdElement().getIdPart();


		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		// ACT
		IReadExecutable<IBaseResource> patientReadExecutable = client.read().resource("Patient").withId("wrong").withAdditionalHeader("Authorization", MOCK_HEADER);
		ForbiddenOperationException forbiddenOperationException = assertThrows(ForbiddenOperationException.class, patientReadExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource("getReadPatientClinicalScopes")
	void testBuildRules_searchPatient_providedJwtContainsReadScopesButWrongPatientId(Map<String, Object> claims) {

		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		String mockId = mockPatient.getIdElement().getIdPart();

		claims.put("patient", "wrong");
		mockJwtWithClaims(claims);

		IQuery<IBaseBundle> patientReadExecutable = client.search().forResource(Patient.class)
				.where(Patient.RES_ID.exactly().code(mockId)).withAdditionalHeader("Authorization", MOCK_HEADER);

		ForbiddenOperationException forbiddenOperationException = assertThrows(ForbiddenOperationException.class,
				patientReadExecutable::execute);

		// ASSERT
		Assertions.assertTrue(forbiddenOperationException.getMessage().contains("HTTP 403"));
	}

	@ParameterizedTest
	@MethodSource("getReadPatientClinicalScopes")
	void testBuildRules_readPatient_providedJwtContainsReadScopesButWrongPatientIdAsAdmin(Map<String, Object> claims) {

		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		String mockId = mockPatient.getIdElement().getIdPart();

		claims.put("patient", "wrong");
		claims.put("group", smartAdminGroupClaim);

		mockJwtWithClaims(claims);

		// ACT
		IReadExecutable<IBaseResource> patientReadExecutable = client.read().resource("Patient").withId(mockId)
				.withAdditionalHeader("Authorization", MOCK_HEADER);
		IBaseResource actualPatient = patientReadExecutable.execute();

		// ASSERT
		assertEquals(mockId, actualPatient.getIdElement().getIdPart());
	}

	@ParameterizedTest
	@MethodSource({"getAllPatientClinicalScopes", "getWriteObservationClinicalScopes"})
	void testBuildRules_createObservationOnPatient_providedJwtContainsWriteScopesAndPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		String mockId = mockPatient.getIdElement().getIdPart();

		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		// ACT
		Observation observation = new Observation();
		observation.setSubject(new Reference(mockPatient.getIdElement()));
		ICreateTyped observationCreateExecutable = client.create().resource(observation).withAdditionalHeader("Authorization", MOCK_HEADER);
		MethodOutcome outcome = observationCreateExecutable.execute();

		// ASSERT
		assertTrue(outcome.getCreated());
	}

	@ParameterizedTest
	@MethodSource("getWritePatientClinicalScopes")
	void testBuildRules_createObservationOnPatient_providedJwtContainsWriteScopesButWrongPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		String mockId = mockPatient.getIdElement().getIdPart();

		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		Observation observation = new Observation();
		observation.setSubject(new Reference(new IdType("mock")));
		ICreateTyped observationCreateExecutable = client.create().resource(observation).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenOperationException = assertThrows(ForbiddenOperationException.class, observationCreateExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource("getWritePatientClinicalScopes")
	void testBuildRules_createObservationOnPatient_providedJwtContainsWriteScopesButWrongPatientIdAsAdmin(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		String mockId = mockPatient.getIdElement().getIdPart();

		claims.put("patient", mockId);
		claims.put("group", smartAdminGroupClaim);

		ourLog.trace("smartAdminGroupClaim->{}", smartAdminGroupClaim);

		mockJwtWithClaims(claims);

		// ACT
		Observation observation = new Observation();
		observation.setSubject(new Reference(mockPatient.getIdElement()));
		ICreateTyped observationCreateExecutable = client.create().resource(observation).withAdditionalHeader("Authorization", MOCK_HEADER);
		MethodOutcome outcome = observationCreateExecutable.execute();

		// ASSERT
		assertTrue(outcome.getCreated());
	}


	@ParameterizedTest
	@MethodSource({"getWritePatientClinicalScopes"})
	void testBuildRules_createObservationOnPatient_providedJwtContainsWriteScopesButNotPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();

		mockJwtWithClaims(claims);

		Observation observation = new Observation();
		observation.setSubject(new Reference(mockPatient.getIdElement()));

		ICreateTyped observationCreateExecutable = client.create().resource(observation).withAdditionalHeader("Authorization", MOCK_HEADER);
		// ACT
		ForbiddenOperationException forbiddenOperationException = assertThrows(ForbiddenOperationException.class, observationCreateExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_BY_RULE_DENY_ALL_REQUESTS_IF_NO_ID_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}


	@ParameterizedTest
	@MethodSource({"getReadPatientClinicalScopes"})
	void testBuildRules_createObservationOnPatient_providedJwtDoesNotContainWriteScope(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		String mockId = mockPatient.getIdElement().getIdPart();


		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		Observation observation = new Observation();
		observation.setSubject(new Reference(mockPatient.getIdElement()));

		ICreateTyped observationCreateExecutable = client.create().resource(observation).withAdditionalHeader("Authorization", MOCK_HEADER);
		// ACT
		ForbiddenOperationException forbiddenOperationException = assertThrows(ForbiddenOperationException.class, observationCreateExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"getAllPatientClinicalScopes", "getWriteObservationClinicalScopes"})
	void testBuildRules_deleteObservationOnPatient_providedJwtContainsWriteScopesAndPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		IBaseResource mockObservation = observationResourceDao.create(new Observation().setSubject(new Reference(mockPatient.getIdElement()))).getResource();

		String mockId = mockPatient.getIdElement().getIdPart();
		claims.put("patient", mockId);

		mockJwtWithClaims(claims);

		Observation observation = new Observation();
		observation.setSubject(new Reference(mockPatient.getIdElement()));
		IDeleteTyped observationDeleteExecutable = client.delete().resourceById(mockObservation.getIdElement()).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ASSERT
		assertDoesNotThrow(observationDeleteExecutable::execute);
	}

	@ParameterizedTest
	@MethodSource({"getAllPatientClinicalScopes", "getWriteObservationClinicalScopes"})
	void testBuildRules_deleteObservationOnPatient_providedJwtContainsWriteScopesAndWrongPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		IBaseResource otherPatient = patientResourceDao.create(new Patient()).getResource();

		String otherId = otherPatient.getIdElement().getIdPart();

		IBaseResource mockObservation = observationResourceDao.create(new Observation().setSubject(new Reference(mockPatient.getIdElement()))).getResource();

		claims.put("patient", otherId);
		mockJwtWithClaims(claims);

		// ACT
		Observation observation = new Observation();
		observation.setSubject(new Reference(mockPatient.getIdElement()));
		IDeleteTyped observationDeleteExecutable = client.delete().resourceById(mockObservation.getIdElement()).withAdditionalHeader("Authorization", MOCK_HEADER);
		// ACT
		ForbiddenOperationException forbiddenOperationException = assertThrows(ForbiddenOperationException.class, observationDeleteExecutable::execute);
		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"getReadPatientClinicalScopes", "getWritePatientClinicalScopes"})
	void testBuildRules_deleteObservationOnPatient_providedJwtDoesNotContainCorrectWritePermissions(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		String mockId = mockPatient.getIdElement().getIdPart();

		IBaseResource mockObservation = observationResourceDao.create(new Observation().setSubject(new Reference(mockPatient.getIdElement()))).getResource();

		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		Observation observation = new Observation();
		observation.setSubject(new Reference(mockPatient.getIdElement()));
		IDeleteTyped observationDeleteExecutable = client.delete().resourceById(mockObservation.getIdElement()).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenOperationException = assertThrows(ForbiddenOperationException.class, observationDeleteExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"getReadPatientClinicalScopes", "getWritePatientClinicalScopes", "getAllPatientClinicalScopes", "getWriteObservationClinicalScopes"})
	void gtestBuildRules_deleteObservationOnPatient_providedJwtDoesNotContainPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		IBaseResource mockObservation = observationResourceDao.create(new Observation().setSubject(new Reference(mockPatient.getIdElement()))).getResource();

		mockJwtWithClaims(claims);

		Observation observation = new Observation();
		observation.setSubject(new Reference(mockPatient.getIdElement()));
		IDeleteTyped observationDeleteExecutable = client.delete().resourceById(mockObservation.getIdElement()).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenOperationException = assertThrows(ForbiddenOperationException.class, observationDeleteExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_BY_RULE_DENY_ALL_REQUESTS_IF_NO_ID_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"getAllPatientClinicalScopes", "getWriteObservationClinicalScopes"})
	void testBuildRules_updateObservationOnPatient_providedJwtContainsWriteScopesAndPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		String mockId = mockPatient.getIdElement().getIdPart();

		Observation mockObservation = (Observation) observationResourceDao.create(new Observation().setSubject(new Reference(mockPatient.getIdElement()))).getResource();

		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		IUpdateExecutable observationUpdateExecutable = client.update().resource(mockObservation.setLanguage("mockLanguage")).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ASSERT
		assertDoesNotThrow(observationUpdateExecutable::execute);
	}

	@ParameterizedTest
	@MethodSource({"getAllPatientClinicalScopes", "getWriteObservationClinicalScopes"})
	void testBuildRules_updateObservationOnPatient_providedJwtContainsWriteScopesAndWrongId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		IBaseResource otherPatient = patientResourceDao.create(new Patient()).getResource();

		Observation mockObservation = (Observation) observationResourceDao.create(new Observation().setSubject(new Reference(mockPatient.getIdElement()))).getResource();
		String otherId = otherPatient.getIdElement().getIdPart();


		claims.put("patient", otherId);
		mockJwtWithClaims(claims);

		IUpdateExecutable observationUpdateExecutable = client.update().resource(mockObservation.setLanguage("mockLanguage")).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenOperationException = assertThrows(ForbiddenOperationException.class, observationUpdateExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"getAllPatientClinicalScopes", "getWriteObservationClinicalScopes"})
	void testBuildRules_updateObservationOnPatient_providedJwtContainsWriteScopesAndNoId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();

		Observation mockObservation = (Observation) observationResourceDao.create(new Observation().setSubject(new Reference(mockPatient.getIdElement()))).getResource();

		mockJwtWithClaims(claims);

		IUpdateExecutable observationUpdateExecutable = client.update().resource(mockObservation.setLanguage("mockLanguage")).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenOperationException = assertThrows(ForbiddenOperationException.class, observationUpdateExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_BY_RULE_DENY_ALL_REQUESTS_IF_NO_ID_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"getReadPatientClinicalScopes", "getWritePatientClinicalScopes"})
	void testBuildRules_updateObservationOnPatient_providedJwtContainsWrongScopes(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		String mockId = mockPatient.getIdElement().getIdPart();

		Observation mockObservation = (Observation) observationResourceDao.create(new Observation().setSubject(new Reference(mockPatient.getIdElement()))).getResource();

		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		IUpdateExecutable observationUpdateExecutable = client.update().resource(mockObservation.setLanguage("mockLanguage")).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenOperationException = assertThrows(ForbiddenOperationException.class, observationUpdateExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"getAllPatientClinicalScopes", "getWriteObservationClinicalScopes"})
	void testBuildRules_conditionalCreateObservationOnPatient_providedJwtContainsWriteScopesAndPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		String mockId = mockPatient.getIdElement().getIdPart();

		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		// ACT
		String uuid = UUID.randomUUID().toString();
		Observation observation = new Observation().setStatus(Observation.ObservationStatus.FINAL);

		observation.addIdentifier(new Identifier().setValue(uuid));
		observation.setSubject(new Reference(mockPatient.getIdElement()));
		ICreateTyped observationCreateExecutable = client.create().resource(observation).conditional().where(Observation.IDENTIFIER.exactly().identifier(uuid)).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ASSERT
		assertDoesNotThrow(observationCreateExecutable::execute);
	}

	@ParameterizedTest
	@MethodSource({"getReadPatientClinicalScopes"})
	void testBuildRules_conditionalCreateObservationOnPatient_providedJwtDoesNotContainWriteScopesAndContainsPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		String mockId = mockPatient.getIdElement().getIdPart();

		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		// ACT
		String uuid = UUID.randomUUID().toString();
		Observation observation = new Observation().setStatus(Observation.ObservationStatus.FINAL);

		observation.addIdentifier(new Identifier().setValue(uuid));
		observation.setSubject(new Reference(mockPatient.getIdElement()));
		ICreateTyped observationCreateExecutable = client.create().resource(observation).conditional().where(Observation.IDENTIFIER.exactly().identifier(uuid)).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenOperationException = assertThrows(ForbiddenOperationException.class, observationCreateExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"getAllPatientClinicalScopes", "getWriteObservationClinicalScopes"})
	void testBuildRules_conditionalCreateObservationOnPatient_providedJwtContainsWriteScopesAndContainsWrongPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		IBaseResource otherPatient = patientResourceDao.create(new Patient()).getResource();
		String otherId = otherPatient.getIdElement().getIdPart();


		claims.put("patient", otherId);
		mockJwtWithClaims(claims);

		// ACT
		String uuid = UUID.randomUUID().toString();
		Observation observation = new Observation().setStatus(Observation.ObservationStatus.FINAL);

		observation.addIdentifier(new Identifier().setValue(uuid));
		observation.setSubject(new Reference(mockPatient.getIdElement()));
		ICreateTyped observationCreateExecutable = client.create().resource(observation).conditional().where(Observation.IDENTIFIER.exactly().identifier(uuid)).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenOperationException = assertThrows(ForbiddenOperationException.class, observationCreateExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"getAllPatientClinicalScopes", "getWriteObservationClinicalScopes"})
	void testBuildRules_conditionalCreateObservationOnPatient_providedJwtContainsWriteScopesNoPatientId(Map<String, Object> claims) {
		mockJwtWithClaims(claims);

		// ACT
		String uuid = UUID.randomUUID().toString();
		Observation observation = new Observation().setStatus(Observation.ObservationStatus.FINAL);

		observation.addIdentifier(new Identifier().setValue(uuid));
		observation.setSubject(new Reference());
		ICreateTyped observationCreateExecutable = client.create().resource(observation).conditional().where(Observation.IDENTIFIER.exactly().identifier(uuid)).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenOperationException = assertThrows(ForbiddenOperationException.class, observationCreateExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_BY_RULE_DENY_ALL_REQUESTS_IF_NO_ID_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}


	@ParameterizedTest
	@MethodSource({"getAllPatientClinicalScopes", "getWriteObservationClinicalScopes"})
	void testBuildRules_conditionalOperationObservationOnPatient_providedJwtContainsWriteScopesAndPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		String mockId = mockPatient.getIdElement().getIdPart();
		Reference patientReference = new Reference(mockPatient.getIdElement());

		IBaseResource mockObservation = observationResourceDao.create(new Observation().setSubject(patientReference)).getResource();


		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		// ACT
		IUpdateExecutable observationUpdateExecutable = client.update().resource(mockObservation).conditional().where(Observation.IDENTIFIER.exactly().identifier(mockObservation.getIdElement().getValue())).withAdditionalHeader("Authorization", MOCK_HEADER);
		IDeleteTyped observationDeleteExecutable = client.delete().resourceConditionalByType(mockObservation.getClass()).where(Observation.IDENTIFIER.exactly().identifier(mockObservation.getIdElement().getValue())).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ASSERT
		assertDoesNotThrow(observationUpdateExecutable::execute);
		assertDoesNotThrow(observationDeleteExecutable::execute);
	}

	@ParameterizedTest
	@MethodSource({"getReadPatientClinicalScopes"})
	void testBuildRules_conditionalOperationObservationOnPatient_providedJwtDoesNotContainWriteScopesAndContainsPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		String mockId = mockPatient.getIdElement().getIdPart();
		Reference patientReference = new Reference(mockPatient.getIdElement());

		String id = UUID.randomUUID().toString();
		Observation mockObservation = new Observation().setSubject(patientReference).addIdentifier(new Identifier().setValue(id));
		mockObservation = (Observation) observationResourceDao.create(mockObservation).getResource();

		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		IUpdateExecutable observationUpdateExecutable = client.update().resource(mockObservation).conditional().where(Observation.IDENTIFIER.exactly().identifier(id)).withAdditionalHeader("Authorization", MOCK_HEADER);
		IDeleteTyped observationDeleteExecutable = client.delete().resourceConditionalByType(mockObservation.getClass()).where(Observation.IDENTIFIER.exactly().identifier(id)).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenUpdateException = assertThrows(ForbiddenOperationException.class, observationUpdateExecutable::execute);
		ForbiddenOperationException forbiddenDeleteException = assertThrows(ForbiddenOperationException.class, observationDeleteExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenUpdateException.getMessage());
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenDeleteException.getMessage());

	}

	@ParameterizedTest
	@MethodSource({"getAllPatientClinicalScopes", "getWriteObservationClinicalScopes"})
	void testBuildRules_conditionalOperationsObservationOnPatient_providedJwtContainsWriteScopesAndContainsWrongPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		Reference patientReference = new Reference(mockPatient.getIdElement());

		String id = UUID.randomUUID().toString();
		Observation mockObservation = new Observation().setSubject(patientReference).addIdentifier(new Identifier().setValue(id));
		mockObservation = (Observation) observationResourceDao.create(mockObservation).getResource();

		IBaseResource otherPatient = patientResourceDao.create(new Patient()).getResource();
		String otherId = otherPatient.getIdElement().getIdPart();

		claims.put("patient", otherId);
		mockJwtWithClaims(claims);

		IUpdateExecutable observationUpdateExecutable = client.update().resource(mockObservation).conditional().where(Observation.IDENTIFIER.exactly().identifier(id)).withAdditionalHeader("Authorization", MOCK_HEADER);
		IDeleteTyped observationDeleteExecutable = client.delete().resourceConditionalByType(mockObservation.getClass()).where(Observation.IDENTIFIER.exactly().identifier(id)).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenUpdateException = assertThrows(ForbiddenOperationException.class, observationUpdateExecutable::execute);
		ForbiddenOperationException forbiddenDeleteException = assertThrows(ForbiddenOperationException.class, observationDeleteExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenUpdateException.getMessage());
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenDeleteException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"getAllPatientClinicalScopes", "getWriteObservationClinicalScopes"})
	void testBuildRules_conditionalOperationsObservationOnPatient_providedJwtContainsWriteScopesNoPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		Reference patientReference = new Reference(mockPatient.getIdElement());

		String id = UUID.randomUUID().toString();
		Observation mockObservation = new Observation().setSubject(patientReference).addIdentifier(new Identifier().setValue(id));
		mockObservation = (Observation) observationResourceDao.create(mockObservation).getResource();

		mockJwtWithClaims(claims);

		IUpdateExecutable observationUpdateExecutable = client.update().resource(mockObservation).conditional().where(Observation.IDENTIFIER.exactly().identifier(id)).withAdditionalHeader("Authorization", MOCK_HEADER);
		IDeleteTyped observationDeleteExecutable = client.delete().resourceConditionalByType(mockObservation.getClass()).where(Observation.IDENTIFIER.exactly().identifier(id)).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenUpdateException = assertThrows(ForbiddenOperationException.class, observationUpdateExecutable::execute);
		ForbiddenOperationException forbiddenDeleteException = assertThrows(ForbiddenOperationException.class, observationDeleteExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_BY_RULE_DENY_ALL_REQUESTS_IF_NO_ID_EXCEPTION_MESSAGE, forbiddenUpdateException.getMessage());
		assertEquals(ACCESS_DENIED_BY_RULE_DENY_ALL_REQUESTS_IF_NO_ID_EXCEPTION_MESSAGE, forbiddenDeleteException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"getReadPractitionerClinicalScopes"})
	void testBuildRules_readOperationOnPractitioner_providedJwtContainsWriteScopesAndPractitionerId(Map<String, Object> claims) {
		// ARRANGE
		Practitioner practitioner = new Practitioner();
		IBaseResource mockPractitioner = practitionerResourceDao.create(practitioner).getResource();
		Reference practitionerReference = new Reference(mockPractitioner.getIdElement());

		IBaseResource expectedPatient = patientResourceDao.create(new Patient().addGeneralPractitioner(practitionerReference)).getResource();
		String id=expectedPatient.getIdElement().getIdPart();

		claims.put("user", mockPractitioner.getIdElement().getIdPart());
		mockJwtWithClaims(claims);

		IReadExecutable<IBaseResource> patientReadExecutable = client.read().resource("Patient").withId(id).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		IBaseResource actualPatient = patientReadExecutable.execute();

		// ASSERT
		assertEquals(expectedPatient.getIdElement().getIdPart(), actualPatient.getIdElement().getIdPart());
	}

	@ParameterizedTest
	@MethodSource({"getReadPractitionerClinicalScopes"})
	void testBuildRules_readOperationOnPractitionerReadPatientObservation_providedJwtContainsWriteScopesAndPractitionerId(Map<String, Object> claims) {
		// ARRANGE
		Practitioner practitioner = new Practitioner();
		IBaseResource mockPractitioner = practitionerResourceDao.create(practitioner).getResource();
		Reference practitionerReference = new Reference(mockPractitioner.getIdElement());

		IBaseResource mockPatient = patientResourceDao.create(new Patient().addGeneralPractitioner(practitionerReference)).getResource();
		Reference patientReference = new Reference(mockPatient.getIdElement());

		Observation mockObservation = new Observation().setSubject(patientReference);
		mockObservation = (Observation) observationResourceDao.create(mockObservation).getResource();
		String id=mockObservation.getIdElement().getIdPart();

		claims.put("user", mockPractitioner.getIdElement().getIdPart());
		mockJwtWithClaims(claims);

		IReadExecutable<IBaseResource> observationReadExecutable = client.read().resource("Observation").withId(id).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenUpdateException = assertThrows(ForbiddenOperationException.class, observationReadExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenUpdateException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"getWritePractitionerClinicalScopes"})
	void testBuildRules_writeOperationOnPractitioner_providedJwtContainsWriteScopesAndPractitionerId(Map<String, Object> claims) {
		// ARRANGE
		Practitioner practitioner = new Practitioner();
		IBaseResource mockPractitioner = practitionerResourceDao.create(practitioner).getResource();
		Reference practitionerReference = new Reference(mockPractitioner.getIdElement());

		IBaseResource expectedPatient = new Patient().addGeneralPractitioner(practitionerReference);

		claims.put("user", mockPractitioner.getIdElement().getIdPart());
		mockJwtWithClaims(claims);

		ICreateTyped patientCreateExecutable = client.create().resource(expectedPatient).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		MethodOutcome actualPatient = patientCreateExecutable.execute();

		// ASSERT
		assertTrue(actualPatient.getCreated());
	}

	@ParameterizedTest
	@MethodSource({"getWritePractitionerClinicalScopes"})
	void testBuildRules_writeOperationOnPractitionerCreatePatientObservation_providedJwtContainsWriteScopesAndPractitionerId(Map<String, Object> claims) {
		// ARRANGE
		Practitioner practitioner = new Practitioner();
		IBaseResource mockPractitioner = practitionerResourceDao.create(practitioner).getResource();
		Reference practitionerReference = new Reference(mockPractitioner.getIdElement());

		IBaseResource mockPatient = patientResourceDao.create(new Patient().addGeneralPractitioner(practitionerReference)).getResource();
		Reference patientReference = new Reference(mockPatient.getIdElement());

		Observation mockObservation = new Observation().setSubject(patientReference);

		claims.put("user", mockPractitioner.getIdElement().getIdPart());
		mockJwtWithClaims(claims);

		ICreateTyped observationReadExecutable = client.create().resource(mockObservation).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenUpdateException = assertThrows(ForbiddenOperationException.class, observationReadExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenUpdateException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"getReadPatientClinicalScopes"})
	void testBuildRules_searchOperation_providedJwtContainsReadScope(Map<String, Object> claims) {
		// ARRANGE

		IBaseResource expectedPatient = patientResourceDao.create(new Patient()).getResource();
		String id=expectedPatient.getIdElement().getIdPart();

		claims.put("patient", id);
		mockJwtWithClaims(claims);

		IQuery<IBaseBundle> patientSearchExecutable = client.search().forResource(Patient.class).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		Bundle searchBundle = (Bundle) patientSearchExecutable.execute();


		// ASSERT
		assertEquals(1, searchBundle.getEntry().size());
		assertEquals(searchBundle.getEntry().get(0).getResource().getIdElement().getIdPart(), id);
	}

	@ParameterizedTest
	@MethodSource({ "getReadPatientClinicalScopes" })
	void testBuildRules_searchOperation_providedJwtContainsReadScope_multiplePatients(Map<String, Object> claims) {
		// ARRANGE

		IBaseResource expectedPatient = patientResourceDao.create(new Patient()).getResource();
		String id = expectedPatient.getIdElement().getIdPart();

		// add a second patient to make sure the narrowing interceptor works
		patientResourceDao.create(new Patient());

		claims.put("patient", id);
		mockJwtWithClaims(claims);

		IQuery<IBaseBundle> patientSearchExecutable = client.search().forResource(Patient.class)
				.withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		Bundle searchBundle = (Bundle) patientSearchExecutable.execute();

		// ASSERT
		assertEquals(1, searchBundle.getEntry().size());
		assertEquals(searchBundle.getEntry().get(0).getResource().getIdElement().getIdPart(), id);
	}

	@Test
	void testBuildRules_searchOperation_providedJwtContainsWriteScope() {
		// ARRANGE

		IBaseResource expectedPatient = patientResourceDao.create(new Patient()).getResource();
		String id=expectedPatient.getIdElement().getIdPart();

		Map<String, Object> claims = new HashMap<>();
		claims.put("patient", id);
		claims.put("scope","patient/Patient.write");
		mockJwtWithClaims(claims);

		IQuery<IBaseBundle> patientSearchExecutable = client.search().forResource(Patient.class).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenOperationException = assertThrows(ForbiddenOperationException.class, patientSearchExecutable::execute);

		// ASSERT
		assertEquals("HTTP 403 : Read scope is required when performing a narrowing search operation", forbiddenOperationException.getMessage());
	}

	@Test
	void testBuildRules_searchOperation_noScope() {
		// ARRANGE

		IBaseResource expectedPatient = patientResourceDao.create(new Patient()).getResource();
		String id=expectedPatient.getIdElement().getIdPart();

		Map<String, Object> claims = new HashMap<>();
		claims.put("patient", id);
		mockJwtWithClaims(claims);

		IQuery<IBaseBundle> patientSearchExecutable = client.search().forResource(Patient.class).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException authenticationException = assertThrows(ForbiddenOperationException.class, patientSearchExecutable::execute);

		// ASSERT
		assertEquals("HTTP 403 : No scope provided", authenticationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"getWriteObservationUnknownScopes"})
	void testBuildRules_createObservationOnPatient_providedJwtContainsWriteScopesAndPatientIdAndUnknownScopes(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient = patientResourceDao.create(new Patient()).getResource();
		String mockId = mockPatient.getIdElement().getIdPart();

		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		// ACT
		Observation observation = new Observation();
		observation.setSubject(new Reference(mockPatient.getIdElement()));
		ICreateTyped observationCreateExecutable = client.create().resource(observation).withAdditionalHeader("Authorization", MOCK_HEADER);
		MethodOutcome outcome = observationCreateExecutable.execute();

		// ASSERT
		assertTrue(outcome.getCreated());
	}

	@Test
	void testBuildRules_searchRecords_wrongPatient_providedJwtContainsReadScopesAndPatientId() {

		Map<String, Object> claims = new HashMap<>();
		claims.put("scope", "patient/*.read");

		// create a patient
		IBaseResource patient = patientResourceDao.create(new Patient()).getResource();
		String patId = patient.getIdElement().getIdPart();

		// create an observation for the patient
		IBaseResource observation = observationResourceDao
				.create(new Observation().setSubject(new Reference(patient.getIdElement()))).getResource();
		String obsId = observation.getIdElement().getIdPart();

		// get a claim for a different patient ID
		claims.put("patient", "wrong");
		// claims.put("patient", patId);
		mockJwtWithClaims(claims);

		ForbiddenOperationException exception = Assertions.assertThrows(ForbiddenOperationException.class, () -> {
			// search for our Observation /Observation?subject=Patient/xxx
			// we should not be able to see these records
			Bundle searchBundle = client.search().forResource(Observation.class)
					.where(Observation.SUBJECT.hasId("Patient/" + patId)).returnBundle(Bundle.class)
					.withAdditionalHeader("Authorization", MOCK_HEADER).execute();
		});

		Assertions.assertTrue(exception.getMessage().contains("HTTP 403"));
	}

	@Test
	void testBuildRules_searchRecords_correctPatient_providedJwtContainsReadScopesAndPatientId() {

		Map<String, Object> claims = new HashMap<>();
		claims.put("scope", "patient/*.read");

		// create a patient
		IBaseResource patient = patientResourceDao.create(new Patient()).getResource();
		String patId = patient.getIdElement().getIdPart();

		// create an observation for the patient
		IBaseResource observation = observationResourceDao
				.create(new Observation().setSubject(new Reference(patient.getIdElement()))).getResource();
		String obsId = observation.getIdElement().getIdPart();

		claims.put("patient", patId);
		mockJwtWithClaims(claims);

		// search for our Observation /Observation?subject=Patient/xxx
		// we should not be able to see these records
		Bundle searchBundle = client.search().forResource(Observation.class)
				.where(Observation.SUBJECT.hasId("Patient/" + patId)).returnBundle(Bundle.class)
				.withAdditionalHeader("Authorization", MOCK_HEADER).execute();

		assertEquals(1, searchBundle.getEntry().size());
		assertEquals(searchBundle.getEntry().get(0).getResource().getIdElement().getIdPart(), obsId);
	}

	@Test
	void testBuildRules_searchRecords_NonExplicitlyAllowedResource() {
		Map<String, Object> claims = new HashMap<>();
		claims.put("scope", "patient/*.read");

		// create a patient
		IBaseResource patient = patientResourceDao.create(new Patient()).getResource();
		String patId = patient.getIdElement().getIdPart();

		claims.put("patient", patId);
		mockJwtWithClaims(claims);

		// create an Endpoint
		IBaseResource endpoint = endpointResourceDao.create(new Endpoint()).getResource();
		String endpointId = endpoint.getIdElement().getIdPart();

		// search for all Endpoints
		{
			IQuery<Bundle> executable = client.search().forResource(Endpoint.class).returnBundle(Bundle.class).withAdditionalHeader("Authorization", MOCK_HEADER);
			assertThrows(ForbiddenOperationException.class, executable::execute);
		}

		{
			// now for a specific Endpoint
			IReadExecutable<Endpoint> executable = client.read().resource(Endpoint.class).withId(endpointId).withAdditionalHeader("Authorization", MOCK_HEADER);
			assertThrows(ForbiddenOperationException.class, executable::execute);
		}
	}

	@Test
	void testBuildRules_searchRecords_ExplicitlyAllowed() {

		Map<String, Object> claims = new HashMap<>();
		claims.put("scope", "patient/*.read");

		// create a patient
		IBaseResource patient = patientResourceDao.create(new Patient()).getResource();
		String patId = patient.getIdElement().getIdPart();

		claims.put("patient", patId);
		mockJwtWithClaims(claims);

		// create an Organization
		IBaseResource org = organizationResourceDao.create(new Organization()).getResource();
		String orgId = org.getIdElement().getIdPart();

		// search for all Organizations
		Bundle searchBundle = client.search().forResource(Organization.class).returnBundle(Bundle.class).withAdditionalHeader("Authorization", MOCK_HEADER).execute();
		assertEquals(1, searchBundle.getEntry().size());
		assertEquals(searchBundle.getEntry().get(0).getResource().getIdElement().getIdPart(), orgId);

		// now search by specific ID
		Organization readOrg = client.read().resource(Organization.class).withId(orgId).withAdditionalHeader("Authorization", MOCK_HEADER).execute();
		assertNotNull(readOrg);
		assertEquals(readOrg.getIdElement().getIdPart(), orgId);

		// make a change and try to update the Org, should fail
		readOrg.setLanguage("Klingon");
		IUpdateExecutable orgUpdateExecutable = client.update().resource(readOrg).withId(orgId).withAdditionalHeader("Authorization", MOCK_HEADER);
		assertThrows(ForbiddenOperationException.class, orgUpdateExecutable::execute);
	}

	@ParameterizedTest
	@MethodSource({ "getPatientStarReadScopes" })
	void test_patient_read_PatientEverything(Map<String, Object> claims) {

		// create a patient
		IBaseResource patient = patientResourceDao.create(new Patient()).getResource();
		String patId = patient.getIdElement().getIdPart();

		String patId2 = patientResourceDao.create(new Patient()).getResource().getIdElement().getIdPart();

		// create an observation for the patient
		IBaseResource observation = observationResourceDao
				.create(new Observation().setSubject(new Reference(patient.getIdElement()))).getResource();
		String obsId = observation.getIdElement().getIdPart();

		claims.put("patient", patId);
		mockJwtWithClaims(claims);

		Bundle searchBundle = client.operation().onInstance("Patient/" + patId).named("$everything").withNoParameters(Parameters.class)
				.returnResourceType(Bundle.class).withAdditionalHeader("Authorization", MOCK_HEADER).execute();

		assertEquals(2, searchBundle.getEntry().size());

		List<String> idsToFind = new ArrayList<>();
		idsToFind.add(patId);
		idsToFind.add(obsId);

		for (BundleEntryComponent bec : searchBundle.getEntry()) {
			Resource res = bec.getResource();
			idsToFind.remove(res.getIdElement().getIdPart());
		}
		assertEquals(0, idsToFind.size());

		// now try a patient everything for a different patient, should throw an exception
		IOperationUntypedWithInput<Bundle> searchExecutable = client.operation().onInstance("Patient/" + patId2).named("$everything").withNoParameters(Parameters.class)
				.returnResourceType(Bundle.class).withAdditionalHeader("Authorization", MOCK_HEADER);

		assertThrows(ForbiddenOperationException.class, searchExecutable::execute);
	}

	private static Stream<Arguments> getReadPatientClinicalScopes() {
		return Stream.of(
				Arguments.of(
						new HashMap<String, String>() {{
							put("scope", "patient/*.read");
						}}
						),
				Arguments.of(
						new HashMap<String, String>() {{
							put("scope", "patient/Patient.read");
						}}
						)
				);
	}

	private static Stream<Arguments> getPatientStarReadScopes() {
		return Stream.of(
				Arguments.of(
						new HashMap<String, String>() {
							{
								put("scope", "patient/*.read");
							}
						}),
				Arguments.of(
						new HashMap<String, String>() {
							{
								put("scope", "patient/*.*");
							}
						}));
	}

	private static Stream<Arguments> getAllPatientClinicalScopes() {
		return Stream.of(
				Arguments.of(
						new HashMap<String, String>() {{
							put("scope", "patient/*.*");
						}}
						),
				Arguments.of(
						new HashMap<String, String>() {{
							put("scope", "patient/*.write");
						}}
						)
				);
	}

	private static Stream<Arguments> getWritePatientClinicalScopes() {
		return Stream.of(
				Arguments.of(
						new HashMap<String, String>() {{
							put("scope", "patient/Patient.*");
						}}
						),
				Arguments.of(
						new HashMap<String, String>() {{
							put("scope", "patient/Patient.write");
						}}
						)
				);
	}

	private static Stream<Arguments> getWriteObservationClinicalScopes() {
		return Stream.of(
				Arguments.of(
						new HashMap<String, String>() {{
							put("scope", "patient/Observation.*");
						}}
						),
				Arguments.of(
						new HashMap<String, String>() {{
							put("scope", "patient/Observation.write");
						}}
						)
				);
	}

	private static Stream<Arguments> getReadPractitionerClinicalScopes() {
		return Stream.of(
				Arguments.of(
						new HashMap<String, String>() {{
							put("scope", "user/*.read");
						}}
						),
				Arguments.of(
						new HashMap<String, String>() {{
							put("scope", "user/Patient.read");
						}}
						),
				Arguments.of(
						new HashMap<String, String>() {{
							put("scope", "user/*.*");
						}}
						)
				);
	}

	private static Stream<Arguments> getWritePractitionerClinicalScopes() {
		return Stream.of(
				Arguments.of(
						new HashMap<String, String>() {{
							put("scope", "user/*.write");

						}}
						),
				Arguments.of(
						new HashMap<String, String>() {{
							put("scope", "user/Patient.write");
						}}
						),
				Arguments.of(
						new HashMap<String, String>() {{
							put("scope", "user/*.*");
						}}
						)
				);
	}

	/**
	 * 
	 * @return return scopes unknown to SMART authorization which may be in the JWT token, such as launch/patient 
	 */
	private static Stream<Arguments> getWriteObservationUnknownScopes() {
		return Stream.of(
				Arguments.of(
						new HashMap<String, String>() {
							{
								put("scope", "launch/patient patient/Observation.*");
							}
						}));
	}


	private Map<String, Object> getJwtHeaders() {
		Map<String, Object> jwtHeaders = new HashMap<>();
		jwtHeaders.put("kid", "rand");
		jwtHeaders.put("typ", "JWT");
		jwtHeaders.put("alg", "RS256");
		return jwtHeaders;
	}

	private void mockJwtWithClaims(Map<String, Object> claims) {
		Jwt mockJwt = new Jwt("foo.bar.foo", Instant.now(), Instant.now().plusSeconds(120), getJwtHeaders(), claims);
		when(mockJwtDecoder.decode(MOCK_JWT)).thenReturn(mockJwt);
	}

}
