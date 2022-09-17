package ca.uhn.fhir.jpa.starter;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.util.BundleUtil;
import org.hl7.fhir.instance.model.api.IBaseBundle;
import org.hl7.fhir.r4.model.HumanName;
import org.hl7.fhir.r4.model.Identifier;
import org.hl7.fhir.r4.model.Patient;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = Application.class, properties = {
	"spring.batch.job.enabled=false",
	"spring.datasource.url=jdbc:h2:mem:tr4",
	"hapi.fhir.fhir_version=r4",
	"spring.main.allow-bean-definition-overriding=true",
	"spring.jpa.properties.hibernate.search.enabled=true",
	"spring.jpa.properties.hibernate.search.backend.type=lucene",
	"spring.jpa.properties.hibernate.search.backend.analysis.configurer=ca.uhn.fhir.jpa.search.HapiHSearchAnalysisConfigurers$HapiLuceneAnalysisConfigurer",
	"spring.jpa.properties.hibernate.search.backend.directory.type=local-filesystem",
	"spring.jpa.properties.hibernate.search.backend.directory.root=target/lucenefiles",
	"spring.jpa.properties.hibernate.search.backend.lucene_version=lucene_current"

})

public class R4TestCase {
	@LocalServerPort
	private int port;

	@Test
	void test() {

		var client = FhirContext.forR4().newRestfulGenericClient("http://localhost:" + port + "/fhir");

		//setup data
		var totalSize = 5;
		var mySystem = "MY_SYSTEM";
		for (int i = 0; i < totalSize; i++) {
			client
				.create()
				.resource(
					new Patient()
						.addIdentifier(new Identifier().setSystem(mySystem).setValue(UUID.randomUUID().toString()))

						.addName(new HumanName().
							addGiven("Test $it").setFamily("Family"))).execute();
		}

		//find all
		org.hl7.fhir.r4.model.Bundle searchResults = (org.hl7.fhir.r4.model.Bundle) client.search()
			.forResource(Patient.class)
			.where(Patient.IDENTIFIER.hasSystemWithAnyCode(mySystem))
			.count(totalSize + 10).execute();
		var list = BundleUtil.toListOfEntries(FhirContext.forR4(), searchResults);
		assertEquals(totalSize, list.size());
		assertNull(searchResults.getLink(IBaseBundle.LINK_NEXT));


		//find pages
		var pageSize = 2;
		searchResults = (org.hl7.fhir.r4.model.Bundle) client.search()
			.forResource(Patient.class)
			.where(Patient.IDENTIFIER.hasSystemWithAnyCode(mySystem))
			.count(pageSize)
			.execute();

		list = BundleUtil.toListOfEntries(FhirContext.forR4(), searchResults);
		assertEquals(pageSize, list.size());
		assertNotNull(searchResults.getLink(IBaseBundle.LINK_NEXT));

	}
}

