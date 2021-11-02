package ca.uhn.fhir.jpa.starter;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.jpa.api.dao.IFhirResourceDao;
import ca.uhn.fhir.rest.api.MethodOutcome;
import ca.uhn.fhir.rest.client.api.IGenericClient;
import ca.uhn.fhir.rest.client.api.ServerValidationModeEnum;
import ca.uhn.fhir.rest.gclient.ICreateTyped;
import ca.uhn.fhir.rest.gclient.IDeleteTyped;
import ca.uhn.fhir.rest.gclient.IReadExecutable;
import ca.uhn.fhir.rest.gclient.IUpdateExecutable;
import ca.uhn.fhir.rest.server.exceptions.ForbiddenOperationException;
import org.hl7.fhir.instance.model.api.IBaseResource;
import org.hl7.fhir.r4.model.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;


@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = Application.class)
class PatientAuthorizationInterceptorTest {

	public static final String ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE = "HTTP 403 : Access denied by rule: Deny all requests that do not match any pre-defined rules";
	public static final String ACCESS_DENIED_BY_RULE_DENY_ALL_REQUESTS_IF_NO_ID_EXCEPTION_MESSAGE = "HTTP 403 : Access denied by rule: Deny ALL Patient requests if no launch context is given!";
	private IGenericClient client;
	private FhirContext ctx;

	@MockBean
	private JwtDecoder mockJwtDecoder;

	@Autowired
	private IFhirResourceDao<Patient> patientResourceDao;

	@Autowired
	private IFhirResourceDao<Observation> observationResourceDao;

	@LocalServerPort
	private int port;

	private static final String MOCK_JWT = "FAKE_TOKEN";
	private static final String MOCK_HEADER = "Bearer " + MOCK_JWT;

	@BeforeEach
	void setUp() {
		ctx = FhirContext.forR4();
		ctx.getRestfulClientFactory().setServerValidationMode(ServerValidationModeEnum.NEVER);
		ctx.getRestfulClientFactory().setSocketTimeout(1200 * 1000);
		String ourServerBase = "http://localhost:" + port + "/fhir/";
		client = ctx.newRestfulGenericClient(ourServerBase);
	}

	@Test
	void testBuildRules_readPatient_noJwtTokenProvided() {
		// ACT
		IReadExecutable<IBaseResource> patientReadExecutable= client.read().resource("Patient").withId("123");
		ForbiddenOperationException forbiddenOperationException=assertThrows(ForbiddenOperationException.class, patientReadExecutable::execute);

		// ASSERT
		assertEquals("HTTP 403 : Access denied by rule: No JWT given", forbiddenOperationException.getMessage());
	}

	@Test
	void testBuildRules_readPatient_jwtTokenContainsOnlyWriteScope() {
		// ARRANGE
		String mockId="123";

		String mockJwtToken = "I.am.JWT";
		String mockHeader = "Bearer " + mockJwtToken;

		HashMap<String, Object> claims = new HashMap<>();
		claims.put("scope", "patient/*.write");
		claims.put("patient", mockId);

		Jwt mockJwt = new Jwt("someValue", Instant.now(), Instant.now().plusSeconds(120), getJwtHeaders(), claims);
		when(mockJwtDecoder.decode(mockJwtToken)).thenReturn(mockJwt);
		// ACT
		IReadExecutable<IBaseResource> patientReadExecutable= client.read().resource("Patient").withId(mockId).withAdditionalHeader("Authorization", mockHeader);
		ForbiddenOperationException forbiddenOperationException=assertThrows(ForbiddenOperationException.class, patientReadExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@Test
	void testBuildRules_readPatient_jwtTokenOnlyContainsSpecificResourcePermissions() {
		// ARRANGE
		String mockId="123";

		String mockJwtToken = "I.am.JWT";
		String mockHeader = "Bearer " + mockJwtToken;

		HashMap<String, Object> claims = new HashMap<>();
		claims.put("scope", "patient/Observation.*");
		claims.put("patient", mockId);

		Jwt mockJwt = new Jwt("someValue", Instant.now(), Instant.now().plusSeconds(120), getJwtHeaders(), claims);
		when(mockJwtDecoder.decode(mockJwtToken)).thenReturn(mockJwt);
		// ACT
		IReadExecutable<IBaseResource> patientReadExecutable= client.read().resource("Patient").withId(mockId).withAdditionalHeader("Authorization", mockHeader);
		ForbiddenOperationException forbiddenOperationException=assertThrows(ForbiddenOperationException.class, patientReadExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@Test
	void testBuildRules_readPatient_emptyClaims() {
		// ARRANGE
		String mockId="123";

		String mockJwtToken = "I.am.JWT";
		String mockHeader = "Bearer " + mockJwtToken;

		HashMap<String, Object> claims = new HashMap<>();
		claims.put("scope", "");

		Jwt mockJwt = new Jwt("someValue", Instant.now(), Instant.now().plusSeconds(120), getJwtHeaders(), claims);
		when(mockJwtDecoder.decode(mockJwtToken)).thenReturn(mockJwt);
		// ACT
		IReadExecutable<IBaseResource> patientReadExecutable= client.read().resource("Patient").withId(mockId).withAdditionalHeader("Authorization", mockHeader);
		ForbiddenOperationException forbiddenOperationException=assertThrows(ForbiddenOperationException.class, patientReadExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource("providePatientReadClaims")
	void testBuildRules_readPatient_jwtTokenContainsReadScopesButNotPatientId(Map<String, Object> claims) {
		// ARRANGE
		String mockJwtToken = "I.am.JWT";
		String mockHeader = "Bearer " + mockJwtToken;

		Jwt mockJwt = new Jwt("someValue", Instant.now(), Instant.now().plusSeconds(120), getJwtHeaders(), claims);
		when(mockJwtDecoder.decode(mockJwtToken)).thenReturn(mockJwt);

		// ACT
		IReadExecutable<IBaseResource> patientReadExecutable= client.read().resource("Patient").withId("123").withAdditionalHeader("Authorization", mockHeader);
		ForbiddenOperationException forbiddenOperationException=assertThrows(ForbiddenOperationException.class, patientReadExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_BY_RULE_DENY_ALL_REQUESTS_IF_NO_ID_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
		}

	@ParameterizedTest
	@MethodSource("providePatientReadClaims")
	void testBuildRules_readPatient_providedJwtContainsReadScopesAndPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient= patientResourceDao.create(new Patient()).getResource();
		String mockId=mockPatient.getIdElement().getIdPart();

		claims.put("patient", mockId);

		mockJwtWithClaims(claims);
		// ACT
		IReadExecutable<IBaseResource> patientReadExecutable= client.read().resource("Patient").withId(mockId).withAdditionalHeader("Authorization", MOCK_HEADER);
		IBaseResource patient=patientReadExecutable.execute();

		// ASSERT
		assertEquals(mockPatient.getIdElement().getIdPart(), patient.getIdElement().getIdPart());
	}

	@ParameterizedTest
	@MethodSource("providePatientReadClaims")
	void testBuildRules_readPatient_providedJwtContainsReadScopesButWrongPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient= patientResourceDao.create(new Patient()).getResource();
		String mockId=mockPatient.getIdElement().getIdPart();


		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		// ACT
		IReadExecutable<IBaseResource> patientReadExecutable= client.read().resource("Patient").withId("wrong").withAdditionalHeader("Authorization", MOCK_HEADER);
		ForbiddenOperationException forbiddenOperationException=assertThrows(ForbiddenOperationException.class, patientReadExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}


	@ParameterizedTest
	@MethodSource({"provideAllWriteClaims", "provideObservationWriteClaims"})
	void testBuildRules_createObservationOnPatient_providedJwtContainsWriteScopesAndPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient= patientResourceDao.create(new Patient()).getResource();
		String mockId=mockPatient.getIdElement().getIdPart();

		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		// ACT
		Observation observation = new Observation();
		observation.setSubject(new Reference(mockPatient.getIdElement()));
		ICreateTyped observationCreateExecutable= client.create().resource(observation).withAdditionalHeader("Authorization", MOCK_HEADER);
		MethodOutcome outcome=observationCreateExecutable.execute();

		// ASSERT
		assertTrue(outcome.getCreated());
	}

	@ParameterizedTest
	@MethodSource("providePatientWriteClaims")
	void testBuildRules_createObservationOnPatient_providedJwtContainsWriteScopesButWrongPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient= patientResourceDao.create(new Patient()).getResource();
		String mockId=mockPatient.getIdElement().getIdPart();

		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		Observation observation = new Observation();
		observation.setSubject(new Reference(new IdType("mock")));
		ICreateTyped observationCreateExecutable= client.create().resource(observation).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenOperationException=assertThrows(ForbiddenOperationException.class, observationCreateExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"providePatientWriteClaims"})
	void testBuildRules_createObservationOnPatient_providedJwtContainsWriteScopesButNotPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient= patientResourceDao.create(new Patient()).getResource();

		mockJwtWithClaims(claims);

		Observation observation = new Observation();
		observation.setSubject(new Reference(mockPatient.getIdElement()));

		ICreateTyped observationCreateExecutable= client.create().resource(observation).withAdditionalHeader("Authorization", MOCK_HEADER);
		// ACT
		ForbiddenOperationException forbiddenOperationException=assertThrows(ForbiddenOperationException.class, observationCreateExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_BY_RULE_DENY_ALL_REQUESTS_IF_NO_ID_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}


	@ParameterizedTest
	@MethodSource({"providePatientReadClaims"})
	void testBuildRules_createObservationOnPatient_providedJwtDoesNotContainWriteScope(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient= patientResourceDao.create(new Patient()).getResource();
		String mockId=mockPatient.getIdElement().getIdPart();


		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		Observation observation = new Observation();
		observation.setSubject(new Reference(mockPatient.getIdElement()));

		ICreateTyped observationCreateExecutable= client.create().resource(observation).withAdditionalHeader("Authorization", MOCK_HEADER);
		// ACT
		ForbiddenOperationException forbiddenOperationException=assertThrows(ForbiddenOperationException.class, observationCreateExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"provideAllWriteClaims", "provideObservationWriteClaims"})
	void testBuildRules_deleteObservationOnPatient_providedJwtContainsWriteScopesAndPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient= patientResourceDao.create(new Patient()).getResource();
		IBaseResource mockObservation= observationResourceDao.create(new Observation().setSubject(new Reference(mockPatient.getIdElement()))).getResource();

		String mockId=mockPatient.getIdElement().getIdPart();
		claims.put("patient", mockId);

		mockJwtWithClaims(claims);

		Observation observation = new Observation();
		observation.setSubject(new Reference(mockPatient.getIdElement()));
		IDeleteTyped observationDeleteExecutable= client.delete().resourceById(mockObservation.getIdElement()).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ASSERT
		assertDoesNotThrow(observationDeleteExecutable::execute);
	}

	@ParameterizedTest
	@MethodSource({"provideAllWriteClaims", "provideObservationWriteClaims"})
	void testBuildRules_deleteObservationOnPatient_providedJwtContainsWriteScopesAndWrongPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient= patientResourceDao.create(new Patient()).getResource();
		IBaseResource otherPatient = patientResourceDao.create(new Patient()).getResource();

		String otherId=otherPatient.getIdElement().getIdPart();

		IBaseResource mockObservation=observationResourceDao.create(new Observation().setSubject(new Reference(mockPatient.getIdElement()))).getResource();

		claims.put("patient", otherId);
		mockJwtWithClaims(claims);

		// ACT
		Observation observation = new Observation();
		observation.setSubject(new Reference(mockPatient.getIdElement()));
		IDeleteTyped observationDeleteExecutable= client.delete().resourceById(mockObservation.getIdElement()).withAdditionalHeader("Authorization", MOCK_HEADER);
		// ACT
		ForbiddenOperationException forbiddenOperationException=assertThrows(ForbiddenOperationException.class, observationDeleteExecutable::execute);
		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"providePatientReadClaims", "providePatientWriteClaims"})
	void testBuildRules_deleteObservationOnPatient_providedJwtDoesNotContainCorrectWritePermissions(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient= patientResourceDao.create(new Patient()).getResource();
		String mockId=mockPatient.getIdElement().getIdPart();

		IBaseResource mockObservation= observationResourceDao.create(new Observation().setSubject(new Reference(mockPatient.getIdElement()))).getResource();

		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		Observation observation = new Observation();
		observation.setSubject(new Reference(mockPatient.getIdElement()));
		IDeleteTyped observationDeleteExecutable= client.delete().resourceById(mockObservation.getIdElement()).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenOperationException=assertThrows(ForbiddenOperationException.class, observationDeleteExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"providePatientReadClaims", "providePatientWriteClaims", "provideAllWriteClaims","provideObservationWriteClaims"})
	void gtestBuildRules_deleteObservationOnPatient_providedJwtDoesNotContainPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient= patientResourceDao.create(new Patient()).getResource();
		IBaseResource mockObservation= observationResourceDao.create(new Observation().setSubject(new Reference(mockPatient.getIdElement()))).getResource();

		mockJwtWithClaims(claims);

		Observation observation = new Observation();
		observation.setSubject(new Reference(mockPatient.getIdElement()));
		IDeleteTyped observationDeleteExecutable= client.delete().resourceById(mockObservation.getIdElement()).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenOperationException=assertThrows(ForbiddenOperationException.class, observationDeleteExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_BY_RULE_DENY_ALL_REQUESTS_IF_NO_ID_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"provideAllWriteClaims", "provideObservationWriteClaims"})
	void testBuildRules_updateObservationOnPatient_providedJwtContainsWriteScopesAndPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient= patientResourceDao.create(new Patient()).getResource();
		String mockId=mockPatient.getIdElement().getIdPart();

		Observation mockObservation= (Observation) observationResourceDao.create(new Observation().setSubject(new Reference(mockPatient.getIdElement()))).getResource();

		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		IUpdateExecutable observationUpdateExecutable= client.update().resource(mockObservation.setLanguage("mockLanguage")).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ASSERT
		assertDoesNotThrow(observationUpdateExecutable::execute);
	}

	@ParameterizedTest
	@MethodSource({"provideAllWriteClaims", "provideObservationWriteClaims"})
	void testBuildRules_updateObservationOnPatient_providedJwtContainsWriteScopesAndWrongId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient= patientResourceDao.create(new Patient()).getResource();
		IBaseResource otherPatient= patientResourceDao.create(new Patient()).getResource();

		Observation mockObservation= (Observation) observationResourceDao.create(new Observation().setSubject(new Reference(mockPatient.getIdElement()))).getResource();
		String otherId=otherPatient.getIdElement().getIdPart();


		claims.put("patient", otherId);
		mockJwtWithClaims(claims);

		IUpdateExecutable observationUpdateExecutable= client.update().resource(mockObservation.setLanguage("mockLanguage")).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenOperationException=assertThrows(ForbiddenOperationException.class, observationUpdateExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"provideAllWriteClaims", "provideObservationWriteClaims"})
	void testBuildRules_updateObservationOnPatient_providedJwtContainsWriteScopesAndNoId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient= patientResourceDao.create(new Patient()).getResource();

		Observation mockObservation= (Observation) observationResourceDao.create(new Observation().setSubject(new Reference(mockPatient.getIdElement()))).getResource();

		mockJwtWithClaims(claims);

		IUpdateExecutable observationUpdateExecutable= client.update().resource(mockObservation.setLanguage("mockLanguage")).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenOperationException=assertThrows(ForbiddenOperationException.class, observationUpdateExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_BY_RULE_DENY_ALL_REQUESTS_IF_NO_ID_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"providePatientReadClaims", "providePatientWriteClaims"})
	void testBuildRules_updateObservationOnPatient_providedJwtContainsWrongScopes(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient= patientResourceDao.create(new Patient()).getResource();
		String mockId=mockPatient.getIdElement().getIdPart();

		Observation mockObservation= (Observation) observationResourceDao.create(new Observation().setSubject(new Reference(mockPatient.getIdElement()))).getResource();

		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		IUpdateExecutable observationUpdateExecutable= client.update().resource(mockObservation.setLanguage("mockLanguage")).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenOperationException=assertThrows(ForbiddenOperationException.class, observationUpdateExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"provideAllWriteClaims", "provideObservationWriteClaims"})
	void testBuildRules_conditionalCreateObservationOnPatient_providedJwtContainsWriteScopesAndPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient= patientResourceDao.create(new Patient()).getResource();
		String mockId=mockPatient.getIdElement().getIdPart();

		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		// ACT
		String uuid = UUID.randomUUID().toString();
		Observation observation = new Observation().setStatus(Observation.ObservationStatus.FINAL);

		observation.addIdentifier(new Identifier().setValue(uuid));
		observation.setSubject(new Reference(mockPatient.getIdElement()));
		ICreateTyped observationCreateExecutable= client.create().resource(observation).conditional().where(Observation.IDENTIFIER.exactly().identifier(uuid)).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ASSERT
		assertDoesNotThrow(observationCreateExecutable::execute);
	}

	@ParameterizedTest
	@MethodSource({"providePatientReadClaims"})
	void testBuildRules_conditionalCreateObservationOnPatient_providedJwtDoesNotContainWriteScopesAndContainsPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient= patientResourceDao.create(new Patient()).getResource();
		String mockId=mockPatient.getIdElement().getIdPart();

		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		// ACT
		String uuid = UUID.randomUUID().toString();
		Observation observation = new Observation().setStatus(Observation.ObservationStatus.FINAL);

		observation.addIdentifier(new Identifier().setValue(uuid));
		observation.setSubject(new Reference(mockPatient.getIdElement()));
		ICreateTyped observationCreateExecutable= client.create().resource(observation).conditional().where(Observation.IDENTIFIER.exactly().identifier(uuid)).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenOperationException=assertThrows(ForbiddenOperationException.class, observationCreateExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"provideAllWriteClaims", "provideObservationWriteClaims"})
	void testBuildRules_conditionalCreateObservationOnPatient_providedJwtContainsWriteScopesAndContainsWrongPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient= patientResourceDao.create(new Patient()).getResource();
		IBaseResource otherPatient= patientResourceDao.create(new Patient()).getResource();
		String otherId=otherPatient.getIdElement().getIdPart();


		claims.put("patient", otherId);
		mockJwtWithClaims(claims);

		// ACT
		String uuid = UUID.randomUUID().toString();
		Observation observation = new Observation().setStatus(Observation.ObservationStatus.FINAL);

		observation.addIdentifier(new Identifier().setValue(uuid));
		observation.setSubject(new Reference(mockPatient.getIdElement()));
		ICreateTyped observationCreateExecutable= client.create().resource(observation).conditional().where(Observation.IDENTIFIER.exactly().identifier(uuid)).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenOperationException=assertThrows(ForbiddenOperationException.class, observationCreateExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"provideAllWriteClaims", "provideObservationWriteClaims"})
	void testBuildRules_conditionalCreateObservationOnPatient_providedJwtContainsWriteScopesNoPatientId(Map<String, Object> claims) {
		mockJwtWithClaims(claims);

		// ACT
		String uuid = UUID.randomUUID().toString();
		Observation observation = new Observation().setStatus(Observation.ObservationStatus.FINAL);

		observation.addIdentifier(new Identifier().setValue(uuid));
		observation.setSubject(new Reference());
		ICreateTyped observationCreateExecutable= client.create().resource(observation).conditional().where(Observation.IDENTIFIER.exactly().identifier(uuid)).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenOperationException=assertThrows(ForbiddenOperationException.class, observationCreateExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_BY_RULE_DENY_ALL_REQUESTS_IF_NO_ID_EXCEPTION_MESSAGE, forbiddenOperationException.getMessage());
	}


	@ParameterizedTest
	@MethodSource({"provideAllWriteClaims", "provideObservationWriteClaims"})
	void testBuildRules_conditionalOperationObservationOnPatient_providedJwtContainsWriteScopesAndPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient= patientResourceDao.create(new Patient()).getResource();
		String mockId=mockPatient.getIdElement().getIdPart();
		Reference patientReference = new Reference(mockPatient.getIdElement());

		IBaseResource mockObservation = observationResourceDao.create(new Observation().setSubject(patientReference)).getResource();


		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		// ACT
		IUpdateExecutable observationUpdateExecutable= client.update().resource(mockObservation).conditional().where(Observation.IDENTIFIER.exactly().identifier(mockObservation.getIdElement().getValue())).withAdditionalHeader("Authorization", MOCK_HEADER);
		IDeleteTyped observationDeleteExecutable= client.delete().resourceConditionalByType(mockObservation.getClass()).where(Observation.IDENTIFIER.exactly().identifier(mockObservation.getIdElement().getValue())).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ASSERT
		assertDoesNotThrow(observationUpdateExecutable::execute);
		assertDoesNotThrow(observationDeleteExecutable::execute);
	}

	@ParameterizedTest
	@MethodSource({"providePatientReadClaims", "provideEmptyClaims"})
	void testBuildRules_conditionalOperationObservationOnPatient_providedJwtDoesNotContainWriteScopesAndContainsPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient= patientResourceDao.create(new Patient()).getResource();
		String mockId=mockPatient.getIdElement().getIdPart();
		Reference patientReference = new Reference(mockPatient.getIdElement());

		String id = UUID.randomUUID().toString();
		Observation mockObservation = new Observation().setSubject(patientReference).addIdentifier(new Identifier().setValue(id));
		mockObservation = (Observation) observationResourceDao.create(mockObservation).getResource();

		claims.put("patient", mockId);
		mockJwtWithClaims(claims);

		IUpdateExecutable observationUpdateExecutable= client.update().resource(mockObservation).conditional().where(Observation.IDENTIFIER.exactly().identifier(id)).withAdditionalHeader("Authorization", MOCK_HEADER);
		IDeleteTyped observationDeleteExecutable= client.delete().resourceConditionalByType(mockObservation.getClass()).where(Observation.IDENTIFIER.exactly().identifier(id)).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenUpdateException=assertThrows(ForbiddenOperationException.class, observationUpdateExecutable::execute);
		ForbiddenOperationException forbiddenDeleteException=assertThrows(ForbiddenOperationException.class, observationDeleteExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenUpdateException.getMessage());
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenDeleteException.getMessage());

	}

	@ParameterizedTest
	@MethodSource({"provideAllWriteClaims", "provideObservationWriteClaims"})
	void testBuildRules_conditionalOperationsObservationOnPatient_providedJwtContainsWriteScopesAndContainsWrongPatientId(Map<String, Object> claims) {
		// ARRANGE
		IBaseResource mockPatient= patientResourceDao.create(new Patient()).getResource();
		Reference patientReference = new Reference(mockPatient.getIdElement());

		String id = UUID.randomUUID().toString();
		Observation mockObservation = new Observation().setSubject(patientReference).addIdentifier(new Identifier().setValue(id));
		mockObservation = (Observation) observationResourceDao.create(mockObservation).getResource();

		IBaseResource otherPatient= patientResourceDao.create(new Patient()).getResource();
		String otherId=otherPatient.getIdElement().getIdPart();

		claims.put("patient", otherId);
		mockJwtWithClaims(claims);

		IUpdateExecutable observationUpdateExecutable= client.update().resource(mockObservation).conditional().where(Observation.IDENTIFIER.exactly().identifier(id)).withAdditionalHeader("Authorization", MOCK_HEADER);
		IDeleteTyped observationDeleteExecutable= client.delete().resourceConditionalByType(mockObservation.getClass()).where(Observation.IDENTIFIER.exactly().identifier(id)).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenUpdateException=assertThrows(ForbiddenOperationException.class, observationUpdateExecutable::execute);
		ForbiddenOperationException forbiddenDeleteException=assertThrows(ForbiddenOperationException.class, observationDeleteExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenUpdateException.getMessage());
		assertEquals(ACCESS_DENIED_DUE_TO_SCOPE_RULE_EXCEPTION_MESSAGE, forbiddenDeleteException.getMessage());
	}

	@ParameterizedTest
	@MethodSource({"provideAllWriteClaims", "provideObservationWriteClaims"})
	void testBuildRules_conditionalOperationsObservationOnPatient_providedJwtContainsWriteScopesNoPatientId(Map<String, Object> claims) {
		IBaseResource mockPatient= patientResourceDao.create(new Patient()).getResource();
		Reference patientReference = new Reference(mockPatient.getIdElement());

		String id = UUID.randomUUID().toString();
		Observation mockObservation = new Observation().setSubject(patientReference).addIdentifier(new Identifier().setValue(id));
		mockObservation = (Observation) observationResourceDao.create(mockObservation).getResource();

		mockJwtWithClaims(claims);

		IUpdateExecutable observationUpdateExecutable= client.update().resource(mockObservation).conditional().where(Observation.IDENTIFIER.exactly().identifier(id)).withAdditionalHeader("Authorization", MOCK_HEADER);
		IDeleteTyped observationDeleteExecutable= client.delete().resourceConditionalByType(mockObservation.getClass()).where(Observation.IDENTIFIER.exactly().identifier(id)).withAdditionalHeader("Authorization", MOCK_HEADER);

		// ACT
		ForbiddenOperationException forbiddenUpdateException=assertThrows(ForbiddenOperationException.class, observationUpdateExecutable::execute);
		ForbiddenOperationException forbiddenDeleteException=assertThrows(ForbiddenOperationException.class, observationDeleteExecutable::execute);

		// ASSERT
		assertEquals(ACCESS_DENIED_BY_RULE_DENY_ALL_REQUESTS_IF_NO_ID_EXCEPTION_MESSAGE, forbiddenUpdateException.getMessage());
		assertEquals(ACCESS_DENIED_BY_RULE_DENY_ALL_REQUESTS_IF_NO_ID_EXCEPTION_MESSAGE, forbiddenDeleteException.getMessage());
	}


	private static Stream<Arguments> provideEmptyClaims(){
		return Stream.of(
			Arguments.of(
				new HashMap<String, String>() {{
					put("scope", "");
				}}
			)
		);
	}

	private static Stream<Arguments> providePatientReadClaims(){
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


	private static Stream<Arguments> provideAllWriteClaims(){
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

	private static Stream<Arguments> providePatientWriteClaims(){
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

	private static Stream<Arguments> provideObservationWriteClaims(){
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

	private Map<String, Object> getJwtHeaders() {
		Map<String, Object> jwtHeaders = new HashMap<>();
		jwtHeaders.put("kid", "rand");
		jwtHeaders.put("typ", "JWT");
		jwtHeaders.put("alg", "RS256");
		return jwtHeaders;
	}

	private void mockJwtWithClaims(Map<String, Object> claims){
		Jwt mockJwt = new Jwt("foo.bar.foo", Instant.now(), Instant.now().plusSeconds(120), getJwtHeaders(), claims);
		when(mockJwtDecoder.decode(MOCK_JWT)).thenReturn(mockJwt);
	}

}