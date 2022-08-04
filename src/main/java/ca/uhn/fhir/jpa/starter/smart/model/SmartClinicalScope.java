/**
 * This Source Code Form is subject to the terms of the Mozilla Public License, v.
 * 2.0 with a Healthcare Disclaimer.
 * A copy of the Mozilla Public License, v. 2.0 with the Healthcare Disclaimer can
 * be found under the top level directory, named LICENSE.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 * If a copy of the Healthcare Disclaimer was not distributed with this file, You
 * can obtain one at the project website https://github.com/igia.
 * <p>
 * Copyright (C) 2018-2019 Persistent Systems, Inc.
 */
package ca.uhn.fhir.jpa.starter.smart.model;

import ca.uhn.fhir.jpa.starter.smart.exception.InvalidClinicalScopeException;

public class SmartClinicalScope {

	private static final org.slf4j.Logger ourLog = org.slf4j.LoggerFactory.getLogger(SmartClinicalScope.class);

	private final String compartment;
	private final String resource;
	private final SmartOperationEnum operation;

	public SmartClinicalScope(String compartment, String resource, SmartOperationEnum operation) {
		this.compartment = compartment;
		this.resource = resource;
		this.operation = operation;
	}

	@Override
	public String toString() {
		return "SmartClinicalScope [compartment=" + compartment + ", resource=" + resource + ", operation=" + operation + "]";
	}

	public SmartClinicalScope(String scope) {
		if(scope.matches("([A-z]*/([A-z]*|[*])[.]([*]|[A-z]*))")){
			String[] parts = scope.split("/");
			compartment = parts[0];
			String[] resourceAndOperation = parts[1].split("[.]");
			resource = resourceAndOperation[0];
			operation = SmartOperationEnum.findByValue(resourceAndOperation[1]);
		} else{
			throw new InvalidClinicalScopeException(scope+" is not a valid clinical scope");
		}
	}

	/**
	 * Utility for creating SMART scopes - this method will return null if the scope format is not recognized
	 * @param scope the scope string, ex ) patient/Patient.read, patient/*.read, etc.
	 * @return a SmartClinicalScope if the formatting is valid
	 */
	public static SmartClinicalScope createIfValidSmartClinicalScope(String scope) {

		//this method doesnt do anything special yet, but made it to allow for making smarter determinations
		//if necessary at some point (checking the compartment/resource values, etc.)
		try {
			return new SmartClinicalScope(scope);
		}
		catch(Exception e) {
			ourLog.debug("Ignoring unknown scope: {}", scope);
			return null;
		}
	}

	public String getCompartment(){
		return compartment;
	}

	public String getResource() {
		return resource;
	}

	public SmartOperationEnum getOperation() {
		return operation;
	}

}
