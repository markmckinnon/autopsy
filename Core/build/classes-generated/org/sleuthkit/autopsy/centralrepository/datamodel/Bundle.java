package org.sleuthkit.autopsy.centralrepository.datamodel;
/** Localizable strings for {@link org.sleuthkit.autopsy.centralrepository.datamodel}. */
class Bundle {
    /**
     * @param majorVersion majorVersion
     * @return <i>Bad value for schema version (</i>{@code majorVersion}<i>) - database is corrupt.</i>
     * @see RdbmsCentralRepo
     */
    static String AbstractSqlEamDb_badMajorSchema_message(Object majorVersion) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AbstractSqlEamDb.badMajorSchema.message", majorVersion);
    }
    /**
     * @param minorVersion minorVersion
     * @return <i>Bad value for schema minor version (</i>{@code minorVersion}<i>) - database is corrupt.</i>
     * @see RdbmsCentralRepo
     */
    static String AbstractSqlEamDb_badMinorSchema_message(Object minorVersion) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AbstractSqlEamDb.badMinorSchema.message", minorVersion);
    }
    /**
     * @param platformName platformName
     * @return <i>Currently selected database platform "</i>{@code platformName}<i>" can not be upgraded.</i>
     * @see RdbmsCentralRepo
     */
    static String AbstractSqlEamDb_cannotUpgrage_message(Object platformName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AbstractSqlEamDb.cannotUpgrage.message", platformName);
    }
    /**
     * @return <i>Failed to read schema version for Central Repository.</i>
     * @see RdbmsCentralRepo
     */
    static String AbstractSqlEamDb_failedToReadMajorVersion_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AbstractSqlEamDb.failedToReadMajorVersion.message");
    }
    /**
     * @return <i>Failed to read schema minor version for Central Repository.</i>
     * @see RdbmsCentralRepo
     */
    static String AbstractSqlEamDb_failedToReadMinorVersion_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AbstractSqlEamDb.failedToReadMinorVersion.message");
    }
    /**
     * @return <i>The selected Central Repository is not compatible with the current version of the application, please upgrade the application if you wish to use this Central Repository.</i>
     * @see RdbmsCentralRepo
     */
    static String AbstractSqlEamDb_upgradeSchema_incompatible() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AbstractSqlEamDb.upgradeSchema.incompatible");
    }
    /**
     * @return <i>Disabled</i>
     * @see CentralRepoDbChoice
     */
    static String CentralRepoDbChoice_Disabled_Text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoDbChoice.Disabled.Text");
    }
    /**
     * @return <i>PostgreSQL using multi-user settings</i>
     * @see CentralRepoDbChoice
     */
    static String CentralRepoDbChoice_PostgreSQL_Multiuser_Text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoDbChoice.PostgreSQL_Multiuser.Text");
    }
    /**
     * @return <i>Custom PostgreSQL</i>
     * @see CentralRepoDbChoice
     */
    static String CentralRepoDbChoice_PostgreSQL_Text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoDbChoice.PostgreSQL.Text");
    }
    /**
     * @return <i>SQLite</i>
     * @see CentralRepoDbChoice
     */
    static String CentralRepoDbChoice_Sqlite_Text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoDbChoice.Sqlite.Text");
    }
    /**
     * @return <i>Failed to connect to central repository database.</i>
     * @see CentralRepoDbManager
     */
    static String CentralRepoDbManager_connectionErrorMsg_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoDbManager.connectionErrorMsg.text");
    }
    /**
     * @return <i>Starting events listener...</i>
     * @see CentralRepositoryService
     */
    static String CentralRepositoryService_progressMsg_startingListener() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepositoryService.progressMsg.startingListener");
    }
    /**
     * @return <i>Checking for schema updates...</i>
     * @see CentralRepositoryService
     */
    static String CentralRepositoryService_progressMsg_updatingSchema() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepositoryService.progressMsg.updatingSchema");
    }
    /**
     * @return <i>Finishing adding data to central repository database....</i>
     * @see CentralRepositoryService
     */
    static String CentralRepositoryService_progressMsg_waitingForListeners() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepositoryService.progressMsg.waitingForListeners");
    }
    /**
     * @return <i>Central Repository Service</i>
     * @see CentralRepositoryService
     */
    static String CentralRepositoryService_serviceName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepositoryService.serviceName");
    }
    /**
     * @return <i>Invalid database table name. Name must start with a lowercase letter and can only contain lowercase letters, numbers, and '_'.</i>
     * @see CorrelationAttributeInstance
     */
    static String CorrelationAttributeInstance_invalidName_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationAttributeInstance.invalidName.message");
    }
    /**
     * @return <i>Database name is null.</i>
     * @see CorrelationAttributeInstance
     */
    static String CorrelationAttributeInstance_nullName_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationAttributeInstance.nullName.message");
    }
    /**
     * @return <i>Email Addresses</i>
     * @see CorrelationAttributeUtil
     */
    static String CorrelationAttributeUtil_emailaddresses_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationAttributeUtil.emailaddresses.text");
    }
    /**
     * @return <i>Domain</i>
     * @see CorrelationAttributeInstance
     */
    static String CorrelationType_DOMAIN_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationType.DOMAIN.displayName");
    }
    /**
     * @return <i>Email Address</i>
     * @see CorrelationAttributeInstance
     */
    static String CorrelationType_EMAIL_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationType.EMAIL.displayName");
    }
    /**
     * @return <i>File MD5</i>
     * @see CorrelationAttributeInstance
     */
    static String CorrelationType_FILES_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationType.FILES.displayName");
    }
    /**
     * @return <i>ICCID Number</i>
     * @see CorrelationAttributeInstance
     */
    static String CorrelationType_ICCID_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationType.ICCID.displayName");
    }
    /**
     * @return <i>IMEI Number</i>
     * @see CorrelationAttributeInstance
     */
    static String CorrelationType_IMEI_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationType.IMEI.displayName");
    }
    /**
     * @return <i>IMSI Number</i>
     * @see CorrelationAttributeInstance
     */
    static String CorrelationType_IMSI_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationType.IMSI.displayName");
    }
    /**
     * @return <i>MAC Address</i>
     * @see CorrelationAttributeInstance
     */
    static String CorrelationType_MAC_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationType.MAC.displayName");
    }
    /**
     * @return <i>Os Account</i>
     * @see CorrelationAttributeInstance
     */
    static String CorrelationType_OS_ACCOUNT_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationType.OS_ACCOUNT.displayName");
    }
    /**
     * @return <i>Phone Number</i>
     * @see CorrelationAttributeInstance
     */
    static String CorrelationType_PHONE_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationType.PHONE.displayName");
    }
    /**
     * @return <i>Installed Program</i>
     * @see CorrelationAttributeInstance
     */
    static String CorrelationType_PROG_NAME_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationType.PROG_NAME.displayName");
    }
    /**
     * @return <i>Wireless Network</i>
     * @see CorrelationAttributeInstance
     */
    static String CorrelationType_SSID_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationType.SSID.displayName");
    }
    /**
     * @return <i>USB Device</i>
     * @see CorrelationAttributeInstance
     */
    static String CorrelationType_USBID_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationType.USBID.displayName");
    }
    /**
     * @return <i>Bad</i>
     * @see CorrelationAttributeInstance
     */
    static String EamArtifactInstances_knownStatus_bad() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamArtifactInstances.knownStatus.bad");
    }
    /**
     * @return <i>Known</i>
     * @see CorrelationAttributeInstance
     */
    static String EamArtifactInstances_knownStatus_known() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamArtifactInstances.knownStatus.known");
    }
    /**
     * @return <i>Unknown</i>
     * @see CorrelationAttributeInstance
     */
    static String EamArtifactInstances_knownStatus_unknown() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamArtifactInstances.knownStatus.unknown");
    }
    /**
     * @return <i>Case Name: </i>
     * @see CorrelationCase
     */
    static String EamCase_title_caseDisplayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamCase.title.caseDisplayName");
    }
    /**
     * @return <i>Case Number: </i>
     * @see CorrelationCase
     */
    static String EamCase_title_caseNumber() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamCase.title.caseNumber");
    }
    /**
     * @return <i>Case UUID: </i>
     * @see CorrelationCase
     */
    static String EamCase_title_caseUUID() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamCase.title.caseUUID");
    }
    /**
     * @return <i>Creation Date: </i>
     * @see CorrelationCase
     */
    static String EamCase_title_creationDate() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamCase.title.creationDate");
    }
    /**
     * @return <i>Examiner Email: </i>
     * @see CorrelationCase
     */
    static String EamCase_title_examinerEmail() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamCase.title.examinerEmail");
    }
    /**
     * @return <i>Examiner Name: </i>
     * @see CorrelationCase
     */
    static String EamCase_title_examinerName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamCase.title.examinerName");
    }
    /**
     * @return <i>Examiner Phone: </i>
     * @see CorrelationCase
     */
    static String EamCase_title_examinerPhone() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamCase.title.examinerPhone");
    }
    /**
     * @return <i>Notes: </i>
     * @see CorrelationCase
     */
    static String EamCase_title_notes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamCase.title.notes");
    }
    /**
     * @return <i>Organization: </i>
     * @see CorrelationCase
     */
    static String EamCase_title_org() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamCase.title.org");
    }
    /**
     * @return <i>Unable to connect to Central Repository.</i>
     * @see CentralRepoDbManager
     */
    static String EamDbUtil_centralRepoConnectionFailed_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbUtil.centralRepoConnectionFailed.message");
    }
    /**
     * @return <i> The Central Repository has been disabled.</i>
     * @see CentralRepoDbManager
     */
    static String EamDbUtil_centralRepoDisabled_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbUtil.centralRepoDisabled.message");
    }
    /**
     * @return <i>Failed to upgrade Central Repository.</i>
     * @see CentralRepoDbManager
     */
    static String EamDbUtil_centralRepoUpgradeFailed_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbUtil.centralRepoUpgradeFailed.message");
    }
    /**
     * @return <i>Unable to acquire exclusive lock for Central Repository.</i>
     * @see CentralRepoDbManager
     */
    static String EamDbUtil_exclusiveLockAquisitionFailure_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbUtil.exclusiveLockAquisitionFailure.message");
    }
    /**
     * @return <i>Unnamed</i>
     * @see Persona
     */
    static String Persona_defaultName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Persona.defaultName");
    }
    /**
     * @return <i>Central Repository module is not enabled.</i>
     * @see PostgresCentralRepo
     */
    static String PostgresEamDb_centralRepoDisabled_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PostgresEamDb.centralRepoDisabled.message");
    }
    /**
     * @return <i>Error getting connection to database.</i>
     * @see PostgresCentralRepo
     */
    static String PostgresEamDb_connectionFailed_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PostgresEamDb.connectionFailed.message");
    }
    /**
     * @return <i>Error acquiring database lock</i>
     * @see PostgresCentralRepo
     */
    static String PostgresEamDb_multiUserLockError_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PostgresEamDb.multiUserLockError.message");
    }
    /**
     * @return <i>Central Repository module is not enabled.</i>
     * @see SqliteCentralRepo
     */
    static String SqliteEamDb_centralRepositoryDisabled_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SqliteEamDb.centralRepositoryDisabled.message");
    }
    /**
     * @return <i>Error getting connection to database.</i>
     * @see SqliteCentralRepo
     */
    static String SqliteEamDb_connectionFailedMessage_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SqliteEamDb.connectionFailedMessage.message");
    }
    /**
     * @return <i>Central repository database missing</i>
     * @see SqliteCentralRepo
     */
    static String SqliteEamDb_databaseMissing_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SqliteEamDb.databaseMissing.message");
    }
    private Bundle() {}
}
