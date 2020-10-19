/*
 * Autopsy Forensic Browser
 *
 * Copyright 2020 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.autopsy.integrationtesting.config;

import java.util.List;

/**
 * Configuration for running Integration Tests including things like ingest
 * parameters, datasource locations, cases to create, tests to run, etc.
 */
public class IntegrationTestConfig {


    private final List<TestSuiteConfig> testSuites;
    private final EnvConfig envConfig;

    public IntegrationTestConfig(List<TestSuiteConfig> testSuites, EnvConfig envConfig) {
        this.testSuites = testSuites;
        this.envConfig = envConfig;
    }
    
    /**
     * @return The per-case configuration.
     */
    public List<TestSuiteConfig> getTestSuites() {
        return testSuites;
    }

    public EnvConfig getEnvConfig() {
        return envConfig;
    }
}
