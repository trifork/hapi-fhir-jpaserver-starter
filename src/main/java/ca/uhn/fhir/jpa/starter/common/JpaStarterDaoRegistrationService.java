package ca.uhn.fhir.jpa.starter.common;

import ca.uhn.fhir.jpa.api.dao.DaoRegistrationService;
import ca.uhn.fhir.jpa.api.dao.DaoRegistry;
import ca.uhn.fhir.jpa.api.dao.IFhirResourceDao;
import ca.uhn.fhir.jpa.api.dao.IFhirSystemDao;

public class JpaStarterDaoRegistrationService extends DaoRegistrationService {
	public JpaStarterDaoRegistrationService(DaoRegistry theDaoRegistry) {
		super(theDaoRegistry);
	}

	@Override
	public void registerResourceDao(IFhirResourceDao<?> theResourceDao) {
		// ignore
	}

}
