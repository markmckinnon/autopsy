package org.sleuthkit.autopsy.centralrepository.optionspanel;
/** Localizable strings for {@link org.sleuthkit.autopsy.centralrepository.optionspanel}. */
class Bundle {
    /**
     * @return <i>Add New Organization</i>
     * @see AddNewOrganizationDialog
     */
    static String AddNewOrganizationDialog_addNewOrg_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddNewOrganizationDialog.addNewOrg.msg");
    }
    /**
     * @return <i>Failed to add new organization.</i>
     * @see AddNewOrganizationDialog
     */
    static String AddNewOrganizationDialog_bnOk_addFailed_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddNewOrganizationDialog.bnOk.addFailed.text");
    }
    /**
     * @return <i>Organization Name is required.</i>
     * @see AddNewOrganizationDialog
     */
    static String AddNewOrganizationDialog_validation_incompleteFields() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddNewOrganizationDialog.validation.incompleteFields");
    }
    /**
     * @return <i>Case Name</i>
     * @see CasesTableModel
     */
    static String CasesTableModel_case() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CasesTableModel.case");
    }
    /**
     * @return <i>Creation Date</i>
     * @see CasesTableModel
     */
    static String CasesTableModel_creationDate() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CasesTableModel.creationDate");
    }
    /**
     * @return <i>No Cases</i>
     * @see CasesTableModel
     */
    static String CasesTableModel_noData() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CasesTableModel.noData");
    }
    /**
     * @return <i>Data Source Name</i>
     * @see DataSourcesTableModel
     */
    static String DataSourcesTableModel_dataSource() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourcesTableModel.dataSource");
    }
    /**
     * @return <i>Device ID</i>
     * @see DataSourcesTableModel
     */
    static String DataSourcesTableModel_deviceId() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourcesTableModel.deviceId");
    }
    /**
     * @return <i>No Data Sources</i>
     * @see DataSourcesTableModel
     */
    static String DataSourcesTableModel_noData() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourcesTableModel.noData");
    }
    /**
     * @return <i>Selected database path is invalid. Try again.</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_chooserPath_failedToGetDbPathMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.chooserPath.failedToGetDbPathMsg");
    }
    /**
     * @return <i>Select location for central_repository.db</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_fcDatabasePath_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.fcDatabasePath.title");
    }
    /**
     * @return <i>Database Type :</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_lbDatabaseType_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.lbDatabaseType.text");
    }
    /**
     * @return <i>SQLite should only be used by one examiner at a time.</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_lbSingleUserSqLite_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.lbSingleUserSqLite.text");
    }
    /**
     * @return <i>Failed to connect to central repository database.</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_okButton_connectionErrorMsg_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.okButton.connectionErrorMsg.text");
    }
    /**
     * @return <i>Central Repository Database exists but is not the right format. Manually delete it or choose a different path (if applicable).</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_okButton_corruptDatabaseExists_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.okButton.corruptDatabaseExists.message");
    }
    /**
     * @return <i>Error Loading Central Repository Database</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_okButton_corruptDatabaseExists_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.okButton.corruptDatabaseExists.title");
    }
    /**
     * @return <i>Central Repository Database does not exist, would you like to create it?</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_okButton_createDbDialog_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.okButton.createDbDialog.message");
    }
    /**
     * @return <i>Central Repository Database Does Not Exist</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_okButton_createDbDialog_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.okButton.createDbDialog.title");
    }
    /**
     * @return <i>Unable to Create Central Repository Database</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_okButton_createDbError_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.okButton.createDbError.title");
    }
    /**
     * @return <i>Unable to create Postgres Central Repository Database, please ensure address, port, and login credentials are correct for Postgres server and try again.</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_okButton_createPostgresDbError_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.okButton.createPostgresDbError.message");
    }
    /**
     * @return <i>Unable to create SQLite Central Repository Database, please ensure location exists and you have write permissions and try again.</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_okButton_createSQLiteDbError_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.okButton.createSQLiteDbError.message");
    }
    /**
     * @return <i>Unable to connect to Central Repository Database. Please check your settings and try again.</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_okButton_databaseConnectionFailed_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.okButton.databaseConnectionFailed.message");
    }
    /**
     * @return <i>Central Repository Database Connection Failed</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_okButton_databaseConnectionFailed_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.okButton.databaseConnectionFailed.title");
    }
    /**
     * @return <i>Please restart Autopsy to begin using the new database platform.</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_okButton_errorMsg_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.okButton.errorMsg.text");
    }
    /**
     * @return <i>Restart Required.</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_okButton_errorTitle_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.okButton.errorTitle.text");
    }
    /**
     * @return <i>Database Name</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_textPrompt_dbName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.textPrompt.dbName");
    }
    /**
     * @return <i>Hostname or IP Address</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_textPrompt_hostnameOrIP() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.textPrompt.hostnameOrIP");
    }
    /**
     * @return <i>Database User's Password</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_textPrompt_password() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.textPrompt.password");
    }
    /**
     * @return <i>Port Number</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_textPrompt_port() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.textPrompt.port");
    }
    /**
     * @return <i>Database User</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_textPrompt_user() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.textPrompt.user");
    }
    /**
     * @return <i>Central Repository Database Configuration</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_title_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.title.text");
    }
    /**
     * @return <i>Click OK to save your database settings and return to the Options. Or select a different database type.</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_validation_finished() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.validation.finished");
    }
    /**
     * @return <i>Fill in all values for the selected database.</i>
     * @see EamDbSettingsDialog
     */
    static String EamDbSettingsDialog_validation_incompleteFields() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamDbSettingsDialog.validation.incompleteFields");
    }
    /**
     * @return <i>Error processing value changes.</i>
     * @see EamOptionsPanelController
     */
    static String EamOptionsController_moduleErr() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamOptionsController.moduleErr");
    }
    /**
     * @return <i>Value change processing failed.</i>
     * @see EamOptionsPanelController
     */
    static String EamOptionsController_moduleErr_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EamOptionsController.moduleErr.msg");
    }
    /**
     * @return <i>Configure PostgreSQL</i>
     * @see GlobalSettingsPanel
     */
    static String GlobalSettingsPanel_askForCentralRepoDbChoice_customPostgrestChoice_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GlobalSettingsPanel.askForCentralRepoDbChoice.customPostgrestChoice.text");
    }
    /**
     * @return <i>Disable Central Repository</i>
     * @see GlobalSettingsPanel
     */
    static String GlobalSettingsPanel_askForCentralRepoDbChoice_disableChoice_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GlobalSettingsPanel.askForCentralRepoDbChoice.disableChoice.text");
    }
    /**
     * @return <i>Use SQLite</i>
     * @see GlobalSettingsPanel
     */
    static String GlobalSettingsPanel_askForCentralRepoDbChoice_sqliteChoice_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GlobalSettingsPanel.askForCentralRepoDbChoice.sqliteChoice.text");
    }
    /**
     * @return <i>The Central Repository will be reconfigured to use a local SQLite database.</i>
     * @see GlobalSettingsPanel
     */
    static String GlobalSettingsPanel_onMultiUserChange_disabledMu_description() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GlobalSettingsPanel.onMultiUserChange.disabledMu.description");
    }
    /**
     * @return <i>Press Configure PostgreSQL to change to a PostgreSQL database.</i>
     * @see GlobalSettingsPanel
     */
    static String GlobalSettingsPanel_onMultiUserChange_disabledMu_description2() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GlobalSettingsPanel.onMultiUserChange.disabledMu.description2");
    }
    /**
     * @return <i>Central Repository Change Necessary</i>
     * @see GlobalSettingsPanel
     */
    static String GlobalSettingsPanel_onMultiUserChange_disabledMu_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GlobalSettingsPanel.onMultiUserChange.disabledMu.title");
    }
    /**
     * @param server_name server name
     * @return <i>Do you want to update the Central Repository to use the PostgreSQL server on </i>{@code server_name}<i>?</i>
     * @see GlobalSettingsPanel
     */
    static String GlobalSettingsPanel_onMultiUserChange_enable_description(Object server_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GlobalSettingsPanel.onMultiUserChange.enable.description", server_name);
    }
    /**
     * @return <i>Any data in an existing SQLite Central Repository will not be transferred to the new database.</i>
     * @see GlobalSettingsPanel
     */
    static String GlobalSettingsPanel_onMultiUserChange_enable_description2() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GlobalSettingsPanel.onMultiUserChange.enable.description2");
    }
    /**
     * @return <i>Central Repository</i>
     * @see GlobalSettingsPanel
     */
    static String GlobalSettingsPanel_onMultiUserChange_enable_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GlobalSettingsPanel.onMultiUserChange.enable.title");
    }
    /**
     * @return <i>Database does not exist.</i>
     * @see GlobalSettingsPanel
     */
    static String GlobalSettingsPanel_testCurrentConfiguration_dbDoesNotExist_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GlobalSettingsPanel.testCurrentConfiguration.dbDoesNotExist.message");
    }
    /**
     * @return <i>You cannot change settings while ingest is running.</i>
     * @see GlobalSettingsPanel
     */
    static String GlobalSettingsPanel_validationErrMsg_ingestRunning() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GlobalSettingsPanel.validationErrMsg.ingestRunning");
    }
    /**
     * @return <i>Configure the database to enable this module.</i>
     * @see GlobalSettingsPanel
     */
    static String GlobalSettingsPanel_validationerrMsg_mustConfigure() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GlobalSettingsPanel.validationerrMsg.mustConfigure");
    }
    /**
     * @return <i>Manage Cases</i>
     * @see ManageCasesDialog
     */
    static String ManageCasesDialog_title_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageCasesDialog.title.text");
    }
    /**
     * @return <i>There are no correlation properties enabled.</i>
     * @see ManageCorrelationPropertiesDialog
     */
    static String ManageCorrelationPropertiesDialog_noneSelected() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageCorrelationPropertiesDialog.noneSelected");
    }
    /**
     * @return <i>Error saving updated selections.</i>
     * @see ManageCorrelationPropertiesDialog
     */
    static String ManageCorrelationPropertiesDialog_okbutton_failure() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageCorrelationPropertiesDialog.okbutton.failure");
    }
    /**
     * @return <i>Manage Correlation Properties</i>
     * @see ManageCorrelationPropertiesDialog
     */
    static String ManageCorrelationPropertiesDialog_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageCorrelationPropertiesDialog.title");
    }
    /**
     * @return <i>Close</i>
     * @see ManageOrganizationsDialog
     */
    static String ManageOrganizationsDialog_closeButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageOrganizationsDialog.closeButton.text");
    }
    /**
     * @return <i>Are you sure you want to delete the selected organization from the central repo?</i>
     * @see ManageOrganizationsDialog
     */
    static String ManageOrganizationsDialog_confirmDeletion_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageOrganizationsDialog.confirmDeletion.message");
    }
    /**
     * @return <i>Confirm Deletion</i>
     * @see ManageOrganizationsDialog
     */
    static String ManageOrganizationsDialog_confirmDeletion_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageOrganizationsDialog.confirmDeletion.title");
    }
    /**
     * @return <i>Delete</i>
     * @see ManageOrganizationsDialog
     */
    static String ManageOrganizationsDialog_deleteButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageOrganizationsDialog.deleteButton.text");
    }
    /**
     * @return <i>Edit</i>
     * @see ManageOrganizationsDialog
     */
    static String ManageOrganizationsDialog_editButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageOrganizationsDialog.editButton.text");
    }
    /**
     * @return <i>New</i>
     * @see ManageOrganizationsDialog
     */
    static String ManageOrganizationsDialog_newButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageOrganizationsDialog.newButton.text");
    }
    /**
     * @return <i>Organizations are used to provide additional contact information for the content they are associated with.</i>
     * @see ManageOrganizationsDialog
     */
    static String ManageOrganizationsDialog_orgDescriptionTextArea_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageOrganizationsDialog.orgDescriptionTextArea.text");
    }
    /**
     * @return <i>Organization Details</i>
     * @see ManageOrganizationsDialog
     */
    static String ManageOrganizationsDialog_orgDetailsLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageOrganizationsDialog.orgDetailsLabel.text");
    }
    /**
     * @return <i>Organizations</i>
     * @see ManageOrganizationsDialog
     */
    static String ManageOrganizationsDialog_orgListLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageOrganizationsDialog.orgListLabel.text");
    }
    /**
     * @return <i>Organization Name:</i>
     * @see ManageOrganizationsDialog
     */
    static String ManageOrganizationsDialog_orgNameLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageOrganizationsDialog.orgNameLabel.text");
    }
    /**
     * @return <i>Point of Contact Email:</i>
     * @see ManageOrganizationsDialog
     */
    static String ManageOrganizationsDialog_pocEmailLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageOrganizationsDialog.pocEmailLabel.text");
    }
    /**
     * @return <i>Point of Contact Name:</i>
     * @see ManageOrganizationsDialog
     */
    static String ManageOrganizationsDialog_pocNameLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageOrganizationsDialog.pocNameLabel.text");
    }
    /**
     * @return <i>Point of Contact Phone:</i>
     * @see ManageOrganizationsDialog
     */
    static String ManageOrganizationsDialog_pocPhoneLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageOrganizationsDialog.pocPhoneLabel.text");
    }
    /**
     * @return <i>Manage Organizations</i>
     * @see ManageOrganizationsDialog
     */
    static String ManageOrganizationsDialog_title_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageOrganizationsDialog.title.text");
    }
    /**
     * @return <i>Unable to delete selected organizaiton.</i>
     * @see ManageOrganizationsDialog
     */
    static String ManageOrganizationsDialog_unableToDeleteOrg_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageOrganizationsDialog.unableToDeleteOrg.message");
    }
    /**
     * @return <i>Unable to Delete</i>
     * @see ManageOrganizationsDialog
     */
    static String ManageOrganizationsDialog_unableToDeleteOrg_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageOrganizationsDialog.unableToDeleteOrg.title");
    }
    private Bundle() {}
}
