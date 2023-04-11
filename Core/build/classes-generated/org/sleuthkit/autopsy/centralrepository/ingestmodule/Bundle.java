package org.sleuthkit.autopsy.centralrepository.ingestmodule;
/** Localizable strings for {@link org.sleuthkit.autopsy.centralrepository.ingestmodule}. */
class Bundle {
    /**
     * @return <i>Saves properties to the central repository for later correlation</i>
     * @see CentralRepoIngestModuleFactory
     */
    static String CentralRepoIngestModuleFactory_ingestmodule_desc() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModuleFactory.ingestmodule.desc");
    }
    /**
     * @return <i>Central Repository</i>
     * @see CentralRepoIngestModuleFactory
     */
    static String CentralRepoIngestModuleFactory_ingestmodule_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModuleFactory.ingestmodule.name");
    }
    /**
     * @return <i>Artifact Type</i>
     * @see CentralRepoIngestModuleUtils
     */
    static String CentralRepoIngestModule_artifact_type_inbox_msg_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModule_artifact_type_inbox_msg_header");
    }
    /**
     * @return <i>Case not present in the central repository</i>
     * @see CentralRepoIngestModule
     */
    static String CentralRepoIngestModule_cannotGetCrCaseErrMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModule_cannotGetCrCaseErrMsg");
    }
    /**
     * @return <i>Data source not present in the central repository</i>
     * @see CentralRepoIngestModule
     */
    static String CentralRepoIngestModule_cannotGetCrDataSourceErrMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModule_cannotGetCrDataSourceErrMsg");
    }
    /**
     * @return <i>Mulit-user cases require a PostgreSQL central repository</i>
     * @see CentralRepoDataArtifactIngestModule
     */
    static String CentralRepoIngestModule_crDatabaseTypeMismatch() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModule_crDatabaseTypeMismatch");
    }
    /**
     * @return <i>Error accessing central repository</i>
     * @see CentralRepoDataArtifactIngestModule
     */
    static String CentralRepoIngestModule_crInaccessibleErrMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModule_crInaccessibleErrMsg");
    }
    /**
     * @return <i>Central repository required, but not enabled</i>
     * @see CentralRepoDataArtifactIngestModule
     */
    static String CentralRepoIngestModule_crNotEnabledErrMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModule_crNotEnabledErrMsg");
    }
    /**
     * @return <i>File Name</i>
     * @see CentralRepoIngestModuleUtils
     */
    static String CentralRepoIngestModule_filename_inbox_msg_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModule_filename_inbox_msg_header");
    }
    /**
     * @return <i>MD5 Hash</i>
     * @see CentralRepoIngestModuleUtils
     */
    static String CentralRepoIngestModule_md5Hash_inbox_msg_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModule_md5Hash_inbox_msg_header");
    }
    /**
     * @return <i>Correlation attribute type for files not found in the central repository</i>
     * @see CentralRepoIngestModule
     */
    static String CentralRepoIngestModule_missingFileCorrAttrTypeErrMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModule_missingFileCorrAttrTypeErrMsg");
    }
    /**
     * @return <i>Error getting current case</i>
     * @see CentralRepoDataArtifactIngestModule
     */
    static String CentralRepoIngestModule_noCurrentCaseErrMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModule_noCurrentCaseErrMsg");
    }
    /**
     * @param list_of_cases list of cases
     * @return <i>Previously marked as notable in cases </i>{@code list_of_cases}
     * @see CentralRepoIngestModuleUtils
     */
    static String CentralRepoIngestModule_notableJustification(Object list_of_cases) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModule_notableJustification", list_of_cases);
    }
    /**
     * @return <i>Previously Tagged As Notable (Central Repository)</i>
     * @see CentralRepoIngestModuleUtils
     */
    static String CentralRepoIngestModule_notableSetName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModule_notableSetName");
    }
    /**
     * @return <i>Notable Attribute</i>
     * @see CentralRepoIngestModuleUtils
     */
    static String CentralRepoIngestModule_notable_attr_inbox_msg_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModule_notable_attr_inbox_msg_header");
    }
    /**
     * @param Name_of_item_that_is_Notable Name of item that is Notable
     * @return <i>Notable: </i>{@code Name_of_item_that_is_Notable}
     * @see CentralRepoIngestModuleUtils
     */
    static String CentralRepoIngestModule_notable_inbox_msg_subject(Object Name_of_item_that_is_Notable) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModule_notable_inbox_msg_subject", Name_of_item_that_is_Notable);
    }
    /**
     * @param list_of_cases list of cases
     * @return <i>Previously seen in cases </i>{@code list_of_cases}
     * @see CentralRepoIngestModuleUtils
     */
    static String CentralRepoIngestModule_prevSeenJustification(Object list_of_cases) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModule_prevSeenJustification", list_of_cases);
    }
    /**
     * @return <i>Previously Seen Users (Central Repository)</i>
     * @see CentralRepoDataArtifactIngestModule
     */
    static String CentralRepoIngestModule_prevSeenOsAcctConfig() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModule_prevSeenOsAcctConfig");
    }
    /**
     * @return <i>Users seen in previous cases</i>
     * @see CentralRepoDataArtifactIngestModule
     */
    static String CentralRepoIngestModule_prevSeenOsAcctSetName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModule_prevSeenOsAcctSetName");
    }
    /**
     * @return <i>Previously Seen (Central Repository)</i>
     * @see CentralRepoIngestModuleUtils
     */
    static String CentralRepoIngestModule_prevSeenSetName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModule_prevSeenSetName");
    }
    /**
     * @return <i>Previously seen in zero cases</i>
     * @see CentralRepoIngestModuleUtils
     */
    static String CentralRepoIngestModule_prevUnseenJustification() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModule_prevUnseenJustification");
    }
    /**
     * @return <i>Previous Cases</i>
     * @see CentralRepoIngestModuleUtils
     */
    static String CentralRepoIngestModule_prev_cases_inbox_msg_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoIngestModule_prev_cases_inbox_msg_header");
    }
    private Bundle() {}
}
