package org.sleuthkit.autopsy.modules.dataSourceIntegrity;
/** Localizable strings for {@link org.sleuthkit.autopsy.modules.dataSourceIntegrity}. */
class Bundle {
    /**
     * @param hashName hashName
     * @param calculatedHashValue calculatedHashValue
     * @return <i>&lt;li>Calculated </i>{@code hashName}<i> hash: </i>{@code calculatedHashValue}<i> &lt;/li></i>
     * @see DataSourceIntegrityIngestModule
     */
    static String DataSourceIntegrityIngestModule_process_calcHashWithType(Object hashName, Object calculatedHashValue) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceIntegrityIngestModule.process.calcHashWithType", hashName, calculatedHashValue);
    }
    /**
     * @param imageName imageName
     * @return <i>&lt;p>Data Source Hash Calculation Results for </i>{@code imageName}<i> &lt;/p></i>
     * @see DataSourceIntegrityIngestModule
     */
    static String DataSourceIntegrityIngestModule_process_calculateHashDone(Object imageName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceIntegrityIngestModule.process.calculateHashDone", imageName);
    }
    /**
     * @param imageName imageName
     * @return <i> Error loading hashes for image </i>{@code imageName}<i> from the database</i>
     * @see DataSourceIntegrityIngestModule
     */
    static String DataSourceIntegrityIngestModule_process_errorLoadingHashes(Object imageName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceIntegrityIngestModule.process.errorLoadingHashes", imageName);
    }
    /**
     * @param imageName imageName
     * @return <i> Error saving hashes for image </i>{@code imageName}<i> to the database</i>
     * @see DataSourceIntegrityIngestModule
     */
    static String DataSourceIntegrityIngestModule_process_errorSavingHashes(Object imageName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceIntegrityIngestModule.process.errorSavingHashes", imageName);
    }
    /**
     * @param hashName hashName
     * @return <i>Error creating message digest for </i>{@code hashName}<i> algorithm</i>
     * @see DataSourceIntegrityIngestModule
     */
    static String DataSourceIntegrityIngestModule_process_hashAlgorithmError(Object hashName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceIntegrityIngestModule.process.hashAlgorithmError", hashName);
    }
    /**
     * @param hashAlgorithm hashAlgorithm
     * @param calculatedHashValue calculatedHashValue
     * @param storedHashValue storedHashValue
     * @return {@code hashAlgorithm}<i> hash verification failed:<br>  Calculated hash: </i>{@code calculatedHashValue}<i><br>  Stored hash: </i>{@code storedHashValue}<i><br></i>
     * @see DataSourceIntegrityIngestModule
     */
    static String DataSourceIntegrityIngestModule_process_hashFailedForArtifact(Object hashAlgorithm, Object calculatedHashValue, Object storedHashValue) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceIntegrityIngestModule.process.hashFailedForArtifact", hashAlgorithm, calculatedHashValue, storedHashValue);
    }
    /**
     * @param calculatedHashValue calculatedHashValue
     * @param storedHashValue storedHashValue
     * @return <i>&lt;ul>&lt;li>Calculated hash: </i>{@code calculatedHashValue}<i> &lt;/li>&lt;li>Stored hash: </i>{@code storedHashValue}<i> &lt;/li>&lt;/ul></i>
     * @see DataSourceIntegrityIngestModule
     */
    static String DataSourceIntegrityIngestModule_process_hashList(Object calculatedHashValue, Object storedHashValue) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceIntegrityIngestModule.process.hashList", calculatedHashValue, storedHashValue);
    }
    /**
     * @param hashName hashName
     * @return <i>&lt;li></i>{@code hashName}<i> hash verified &lt;/li></i>
     * @see DataSourceIntegrityIngestModule
     */
    static String DataSourceIntegrityIngestModule_process_hashMatch(Object hashName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceIntegrityIngestModule.process.hashMatch", hashName);
    }
    /**
     * @param hashName hashName
     * @return <i>&lt;li></i>{@code hashName}<i> hash not verified &lt;/li></i>
     * @see DataSourceIntegrityIngestModule
     */
    static String DataSourceIntegrityIngestModule_process_hashNonMatch(Object hashName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceIntegrityIngestModule.process.hashNonMatch", hashName);
    }
    /**
     * @return <i> hashes calculated</i>
     * @see DataSourceIntegrityIngestModule
     */
    static String DataSourceIntegrityIngestModule_process_hashesCalculated() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceIntegrityIngestModule.process.hashesCalculated");
    }
    /**
     * @param imageName imageName
     * @return <i>Not computing new hashes for </i>{@code imageName}<i> since the option was disabled</i>
     * @see DataSourceIntegrityIngestModule
     */
    static String DataSourceIntegrityIngestModule_process_skipCompute(Object imageName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceIntegrityIngestModule.process.skipCompute", imageName);
    }
    /**
     * @param imageName imageName
     * @return <i>Not verifying existing hashes for </i>{@code imageName}<i> since the option was disabled</i>
     * @see DataSourceIntegrityIngestModule
     */
    static String DataSourceIntegrityIngestModule_process_skipVerify(Object imageName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceIntegrityIngestModule.process.skipVerify", imageName);
    }
    /**
     * @param imageName imageName
     * @return {@code imageName}<i> failed integrity verification</i>
     * @see DataSourceIntegrityIngestModule
     */
    static String DataSourceIntegrityIngestModule_process_verificationFailure(Object imageName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceIntegrityIngestModule.process.verificationFailure", imageName);
    }
    /**
     * @param imageName imageName
     * @return <i>Integrity of </i>{@code imageName}<i> verified</i>
     * @see DataSourceIntegrityIngestModule
     */
    static String DataSourceIntegrityIngestModule_process_verificationSuccess(Object imageName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceIntegrityIngestModule.process.verificationSuccess", imageName);
    }
    /**
     * @return <i>At least one of the checkboxes must be selected</i>
     * @see DataSourceIntegrityIngestModule
     */
    static String DataSourceIntegrityIngestModule_startup_noCheckboxesSelected() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceIntegrityIngestModule.startup.noCheckboxesSelected");
    }
    private Bundle() {}
}
