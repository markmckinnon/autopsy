package org.sleuthkit.autopsy.casemodule;
/** Localizable strings for {@link org.sleuthkit.autopsy.casemodule}. */
class Bundle {
    /**
     * @return <i>Configure Ingest</i>
     * @see AddImageWizardIngestConfigPanel
     */
    static String AddImageWizardIngestConfigPanel_name_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddImageWizardIngestConfigPanel.name.text");
    }
    /**
     * @return <i>This type of Data Source Processor is not available in multi-user mode</i>
     * @see AddImageWizardSelectDspVisual
     */
    static String AddImageWizardSelectDspVisual_multiUserWarning_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddImageWizardSelectDspVisual.multiUserWarning.text");
    }
    /**
     * @return <i>Select Host To Add The Data Source To</i>
     * @see AddImageWizardSelectHostPanel
     */
    static String AddImageWizardSelectHostPanel_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddImageWizardSelectHostPanel_title");
    }
    /**
     * @return <i>Please select an existing host.</i>
     * @see AddImageWizardSelectHostVisual
     */
    static String AddImageWizardSelectHostVisual_getValidationMessage_noHostSelected() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddImageWizardSelectHostVisual_getValidationMessage_noHostSelected");
    }
    /**
     * @return <i>Select Host</i>
     * @see AddImageWizardSelectHostVisual
     */
    static String AddImageWizardSelectHostVisual_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddImageWizardSelectHostVisual_title");
    }
    /**
     * @return <i>Open Case</i>
     * @see CaseOpenAction
     */
    static String CTL_CaseOpenAction() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CTL_CaseOpenAction");
    }
    /**
     * @return <i>Unpack and Open Portable Case</i>
     * @see UnpackagePortableCaseAction
     */
    static String CTL_UnpackagePortableCaseAction() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CTL_UnpackagePortableCaseAction");
    }
    /**
     * @return <i>Case</i>
     * @see CaseDetailsPanel
     */
    static String CaseDetailsPanel_casePanel_border_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseDetailsPanel.casePanel.border.title");
    }
    /**
     * @return <i>Name:</i>
     * @see CaseDetailsPanel
     */
    static String CaseDetailsPanel_examinerLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseDetailsPanel.examinerLabel.text");
    }
    /**
     * @return <i>Examiner</i>
     * @see CaseDetailsPanel
     */
    static String CaseDetailsPanel_examinerPanel_border_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseDetailsPanel.examinerPanel.border.title");
    }
    /**
     * @return <i>Case UUID:</i>
     * @see CaseDetailsPanel
     */
    static String CaseDetailsPanel_lbCaseUUIDLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseDetailsPanel.lbCaseUUIDLabel.text");
    }
    /**
     * @return <i>Email:</i>
     * @see CaseDetailsPanel
     */
    static String CaseDetailsPanel_lbExaminerEmailLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseDetailsPanel.lbExaminerEmailLabel.text");
    }
    /**
     * @return <i>Phone:</i>
     * @see CaseDetailsPanel
     */
    static String CaseDetailsPanel_lbExaminerPhoneLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseDetailsPanel.lbExaminerPhoneLabel.text");
    }
    /**
     * @return <i>Notes:</i>
     * @see CaseDetailsPanel
     */
    static String CaseDetailsPanel_lbNotesLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseDetailsPanel.lbNotesLabel.text");
    }
    /**
     * @return <i>Name:</i>
     * @see CaseDetailsPanel
     */
    static String CaseDetailsPanel_lbOrganizationNameLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseDetailsPanel.lbOrganizationNameLabel.text");
    }
    /**
     * @return <i>Email:</i>
     * @see CaseDetailsPanel
     */
    static String CaseDetailsPanel_lbPointOfContactEmailLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseDetailsPanel.lbPointOfContactEmailLabel.text");
    }
    /**
     * @return <i>Point of Contact:</i>
     * @see CaseDetailsPanel
     */
    static String CaseDetailsPanel_lbPointOfContactNameLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseDetailsPanel.lbPointOfContactNameLabel.text");
    }
    /**
     * @return <i>Phone:</i>
     * @see CaseDetailsPanel
     */
    static String CaseDetailsPanel_lbPointOfContactPhoneLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseDetailsPanel.lbPointOfContactPhoneLabel.text");
    }
    /**
     * @return <i>Organization</i>
     * @see CaseDetailsPanel
     */
    static String CaseDetailsPanel_pnOrganization_border_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseDetailsPanel.pnOrganization.border.title");
    }
    /**
     * @return <i>Details</i>
     * @see CaseInformationPanel
     */
    static String CaseInformationPanel_caseDetails_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseInformationPanel.caseDetails.header");
    }
    /**
     * @return <i>Edit Details</i>
     * @see CaseInformationPanel
     */
    static String CaseInformationPanel_editDetailsButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseInformationPanel.editDetailsButton.text");
    }
    /**
     * @return <i>Edit Case Details</i>
     * @see CaseInformationPanel
     */
    static String CaseInformationPanel_editDetailsDialog_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseInformationPanel.editDetailsDialog.title");
    }
    /**
     * @return <i>Error Opening Case</i>
     * @see OpenRecentCasePanel
     */
    static String CaseOpenAction_msgDlg_cantOpenCase_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseOpenAction.msgDlg.cantOpenCase.title");
    }
    /**
     * @return <i>Multi-user case</i>
     * @see Case
     */
    static String Case_caseType_multiUser() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case_caseType_multiUser");
    }
    /**
     * @return <i>Single-user case</i>
     * @see Case
     */
    static String Case_caseType_singleUser() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case_caseType_singleUser");
    }
    /**
     * @param exception_message exception message
     * @return <i>Error closing case: </i>{@code exception_message}
     * @see Case
     */
    static String Case_closeException_couldNotCloseCase(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.closeException.couldNotCloseCase", exception_message);
    }
    /**
     * @return <i>Failed to get lock on case resources</i>
     * @see Case
     */
    static String Case_creationException_couldNotAcquireResourcesLock() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.creationException.couldNotAcquireResourcesLock");
    }
    /**
     * @return <i>Are you sure you want to close and delete the current case?</i>
     * @see CaseDeleteAction
     */
    static String Case_deleteCaseConfirmationDialog_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.deleteCaseConfirmationDialog.message");
    }
    /**
     * @return <i>Delete Current Case?</i>
     * @see CaseDeleteAction
     */
    static String Case_deleteCaseConfirmationDialog_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.deleteCaseConfirmationDialog.title");
    }
    /**
     * @param exception_message exception message
     * @return <i>Error deleting case: </i>{@code exception_message}
     * @see CaseDeleteAction
     */
    static String Case_deleteCaseFailureMessageBox_message(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.deleteCaseFailureMessageBox.message", exception_message);
    }
    /**
     * @return <i>Failed to Delete Case</i>
     * @see CaseDeleteAction
     */
    static String Case_deleteCaseFailureMessageBox_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.deleteCaseFailureMessageBox.title");
    }
    /**
     * @return <i>Cancelled.</i>
     * @see Case
     */
    static String Case_exceptionMessage_cancelled() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.cancelled");
    }
    /**
     * @return <i>Cannot delete current case, it must be closed first.</i>
     * @see Case
     */
    static String Case_exceptionMessage_cannotDeleteCurrentCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.cannotDeleteCurrentCase");
    }
    /**
     * @return <i>Cannot delete case because it is open for another user or host.</i>
     * @see Case
     */
    static String Case_exceptionMessage_cannotGetLockToDeleteCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.cannotGetLockToDeleteCase");
    }
    /**
     * @return <i>Cannot locate main application window</i>
     * @see Case
     */
    static String Case_exceptionMessage_cannotLocateMainWindow() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.cannotLocateMainWindow");
    }
    /**
     * @return <i>Multi-user settings are missing (see Tools, Options, Multi-user tab), cannot open a multi-user case.</i>
     * @see Case
     */
    static String Case_exceptionMessage_cannotOpenMultiUserCaseNoSettings() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.cannotOpenMultiUserCaseNoSettings");
    }
    /**
     * @param exception_message exception message
     * @return <i>Failed to create collaboration monitor:<br></i>{@code exception_message}<i>.</i>
     * @see Case
     */
    static String Case_exceptionMessage_couldNotCreatCollaborationMonitor(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.couldNotCreatCollaborationMonitor", exception_message);
    }
    /**
     * @param exception_message exception message
     * @return <i>Failed to create case database:<br></i>{@code exception_message}<i>.</i>
     * @see Case
     */
    static String Case_exceptionMessage_couldNotCreateCaseDatabase(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.couldNotCreateCaseDatabase", exception_message);
    }
    /**
     * @param exception_message exception message
     * @return <i>Failed to create coordination service node data:<br></i>{@code exception_message}<i>.</i>
     * @see Case
     */
    static String Case_exceptionMessage_couldNotCreateCaseNodeData(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.couldNotCreateCaseNodeData", exception_message);
    }
    /**
     * @param exception_message exception message
     * @return <i>Failed to get case database server conneciton info:<br></i>{@code exception_message}<i>.</i>
     * @see Case
     */
    static String Case_exceptionMessage_couldNotGetDbServerConnectionInfo(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.couldNotGetDbServerConnectionInfo", exception_message);
    }
    /**
     * @param exception_message exception message
     * @return <i>Failed to open case database:<br></i>{@code exception_message}<i>.</i>
     * @see Case
     */
    static String Case_exceptionMessage_couldNotOpenCaseDatabase(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.couldNotOpenCaseDatabase", exception_message);
    }
    /**
     * @param exception_message exception message
     * @return <i>Failed to open remote events channel:<br></i>{@code exception_message}<i>.</i>
     * @see Case
     */
    static String Case_exceptionMessage_couldNotOpenRemoteEventChannel(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.couldNotOpenRemoteEventChannel", exception_message);
    }
    /**
     * @param exception_message exception message
     * @return <i>Failed to save case metadata:<br></i>{@code exception_message}<i>.</i>
     * @see Case
     */
    static String Case_exceptionMessage_couldNotSaveCaseMetadata(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.couldNotSaveCaseMetadata", exception_message);
    }
    /**
     * @param exception_message exception message
     * @return <i>Failed to save case database name to case metadata file:<br></i>{@code exception_message}<i>.</i>
     * @see Case
     */
    static String Case_exceptionMessage_couldNotSaveDbNameToMetadataFile(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.couldNotSaveDbNameToMetadataFile", exception_message);
    }
    /**
     * @param exception_message exception message
     * @return <i>Failed to update coordination service node data:<br></i>{@code exception_message}<i>.</i>
     * @see Case
     */
    static String Case_exceptionMessage_couldNotUpdateCaseNodeData(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.couldNotUpdateCaseNodeData", exception_message);
    }
    /**
     * @return <i>The data source was not found.</i>
     * @see Case
     */
    static String Case_exceptionMessage_dataSourceNotFound() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.dataSourceNotFound");
    }
    /**
     * @param case_display_name case display name
     * @return <i>Deletion of the case </i>{@code case_display_name}<i> was cancelled.</i>
     * @see Case
     */
    static String Case_exceptionMessage_deletionInterrupted(Object case_display_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.deletionInterrupted", case_display_name);
    }
    /**
     * @return <i>Must specify a case directory path.</i>
     * @see Case
     */
    static String Case_exceptionMessage_emptyCaseDir() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.emptyCaseDir");
    }
    /**
     * @return <i>Must specify a case name.</i>
     * @see Case
     */
    static String Case_exceptionMessage_emptyCaseName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.emptyCaseName");
    }
    /**
     * @return <i>An error occurred while removing the data source from the case database.</i>
     * @see Case
     */
    static String Case_exceptionMessage_errorDeletingDataSourceFromCaseDb() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.errorDeletingDataSourceFromCaseDb");
    }
    /**
     * @return <i>An error occurred while removing the data source from the text index.</i>
     * @see Case
     */
    static String Case_exceptionMessage_errorDeletingDataSourceFromTextIndex() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.errorDeletingDataSourceFromTextIndex");
    }
    /**
     * @return <i>Errors occured while deleting the case. See the application log for details.</i>
     * @see Case
     */
    static String Case_exceptionMessage_errorsDeletingCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.errorsDeletingCase");
    }
    /**
     * @param exception_message exception message
     * @return {@code exception_message}
     * @see Case
     */
    static String Case_exceptionMessage_execExceptionWrapperMessage(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.execExceptionWrapperMessage", exception_message);
    }
    /**
     * @param exception_message exception message
     * @return <i>Failed to connect to coordination service:<br></i>{@code exception_message}<i>.</i>
     * @see Case
     */
    static String Case_exceptionMessage_failedToConnectToCoordSvc(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.failedToConnectToCoordSvc", exception_message);
    }
    /**
     * @param exception_message exception message
     * @return <i>Failed to fetch coordination service node data:<br></i>{@code exception_message}<i>.</i>
     * @see Case
     */
    static String Case_exceptionMessage_failedToFetchCoordSvcNodeData(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.failedToFetchCoordSvcNodeData", exception_message);
    }
    /**
     * @param exception_message exception message
     * @return <i>Failed to exclusively lock case for deletion:<br></i>{@code exception_message}<i>.</i>
     * @see Case
     */
    static String Case_exceptionMessage_failedToLockCaseForDeletion(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.failedToLockCaseForDeletion", exception_message);
    }
    /**
     * @param exception_message exception message
     * @return <i>Failed to read case metadata:<br></i>{@code exception_message}<i>.</i>
     * @see Case
     */
    static String Case_exceptionMessage_failedToReadMetadata(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.failedToReadMetadata", exception_message);
    }
    /**
     * @return <i>Failed to update case metadata</i>
     * @see Case
     */
    static String Case_exceptionMessage_metadataUpdateError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.metadataUpdateError");
    }
    /**
     * @param exception_message exception message
     * @return <i>Unsupported case database schema version:<br></i>{@code exception_message}<i>.</i>
     * @see Case
     */
    static String Case_exceptionMessage_unsupportedSchemaVersionMessage(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.exceptionMessage.unsupportedSchemaVersionMessage", exception_message);
    }
    /**
     * @return <i>Failed to get an exclusive lock on the case.</i>
     * @see Case
     */
    static String Case_lockingException_couldNotAcquireExclusiveLock() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.lockingException.couldNotAcquireExclusiveLock");
    }
    /**
     * @return <i>Failed to get a shared lock on the case.</i>
     * @see Case
     */
    static String Case_lockingException_couldNotAcquireSharedLock() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.lockingException.couldNotAcquireSharedLock");
    }
    /**
     * @param image image
     * @return <i>Opening all filesystems for image: </i>{@code image}<i>...</i>
     * @see Case
     */
    static String Case_openFileSystems_openingImage(Object image) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.openFileSystems.openingImage", image);
    }
    /**
     * @param _case case
     * @return <i>Retrieving images for case: </i>{@code _case}<i>...</i>
     * @see Case
     */
    static String Case_openFileSystems_retrievingImages(Object _case) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.openFileSystems.retrievingImages", _case);
    }
    /**
     * @return <i>Cannot open a multi-user case if multi-user cases are not enabled. See Tools, Options, Multi-User.</i>
     * @see Case
     */
    static String Case_open_exception_multiUserCaseNotEnabled() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.open.exception.multiUserCaseNotEnabled");
    }
    /**
     * @return <i>Cancel</i>
     * @see Case
     */
    static String Case_progressIndicatorCancelButton_label() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressIndicatorCancelButton.label");
    }
    /**
     * @return <i>Closing Case</i>
     * @see Case
     */
    static String Case_progressIndicatorTitle_closingCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressIndicatorTitle.closingCase");
    }
    /**
     * @return <i>Creating Case</i>
     * @see Case
     */
    static String Case_progressIndicatorTitle_creatingCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressIndicatorTitle.creatingCase");
    }
    /**
     * @return <i>Deleting Case</i>
     * @see Case
     */
    static String Case_progressIndicatorTitle_deletingCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressIndicatorTitle.deletingCase");
    }
    /**
     * @return <i>Removing Data Source</i>
     * @see Case
     */
    static String Case_progressIndicatorTitle_deletingDataSource() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressIndicatorTitle.deletingDataSource");
    }
    /**
     * @return <i>Opening Case</i>
     * @see Case
     */
    static String Case_progressIndicatorTitle_openingCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressIndicatorTitle.openingCase");
    }
    /**
     * @return <i>Cancelling...</i>
     * @see Case
     */
    static String Case_progressMessage_cancelling() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.cancelling");
    }
    /**
     * @return <i>Clearing case temp directory...</i>
     * @see Case
     */
    static String Case_progressMessage_clearingTempDirectory() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.clearingTempDirectory");
    }
    /**
     * @return <i>Closing case-specific application service resources...</i>
     * @see Case
     */
    static String Case_progressMessage_closingApplicationServiceResources() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.closingApplicationServiceResources");
    }
    /**
     * @return <i>Closing case database...</i>
     * @see Case
     */
    static String Case_progressMessage_closingCaseDatabase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.closingCaseDatabase");
    }
    /**
     * @return <i>Connecting to coordination service...</i>
     * @see Case
     */
    static String Case_progressMessage_connectingToCoordSvc() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.connectingToCoordSvc");
    }
    /**
     * @return <i>Creating case database...</i>
     * @see Case
     */
    static String Case_progressMessage_creatingCaseDatabase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.creatingCaseDatabase");
    }
    /**
     * @return <i>Creating case directory...</i>
     * @see Case
     */
    static String Case_progressMessage_creatingCaseDirectory() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.creatingCaseDirectory");
    }
    /**
     * @return <i>Creating coordination service node data...</i>
     * @see Case
     */
    static String Case_progressMessage_creatingCaseNodeData() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.creatingCaseNodeData");
    }
    /**
     * @return <i>Deleting case database...</i>
     * @see Case
     */
    static String Case_progressMessage_deletingCaseDatabase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.deletingCaseDatabase");
    }
    /**
     * @return <i>Deleting case directory coordination service node...</i>
     * @see Case
     */
    static String Case_progressMessage_deletingCaseDirCoordSvcNode() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.deletingCaseDirCoordSvcNode");
    }
    /**
     * @return <i>Deleting case directory...</i>
     * @see Case
     */
    static String Case_progressMessage_deletingCaseDirectory() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.deletingCaseDirectory");
    }
    /**
     * @return <i>Removing the data source from the case...</i>
     * @see Case
     */
    static String Case_progressMessage_deletingDataSource() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.deletingDataSource");
    }
    /**
     * @return <i>Deleting case resources coordination service node...</i>
     * @see Case
     */
    static String Case_progressMessage_deletingResourcesCoordSvcNode() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.deletingResourcesCoordSvcNode");
    }
    /**
     * @return <i>Deleting text index...</i>
     * @see Case
     */
    static String Case_progressMessage_deletingTextIndex() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.deletingTextIndex");
    }
    /**
     * @return <i>Fetching coordination service node data for the case...</i>
     * @see Case
     */
    static String Case_progressMessage_fetchingCoordSvcNodeData() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.fetchingCoordSvcNodeData");
    }
    /**
     * @return <i>Opening application service case resources...</i>
     * @see Case
     */
    static String Case_progressMessage_openingApplicationServiceResources() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.openingApplicationServiceResources");
    }
    /**
     * @return <i>Opening case database...</i>
     * @see Case
     */
    static String Case_progressMessage_openingCaseDatabase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.openingCaseDatabase");
    }
    /**
     * @return <i>Opening case-level services...</i>
     * @see Case
     */
    static String Case_progressMessage_openingCaseLevelServices() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.openingCaseLevelServices");
    }
    /**
     * @return <i>Preparing...</i>
     * @see Case
     */
    static String Case_progressMessage_preparing() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.preparing");
    }
    /**
     * @return <i>Removing case from Recent Cases menu...</i>
     * @see Case
     */
    static String Case_progressMessage_removingCaseFromRecentCases() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.removingCaseFromRecentCases");
    }
    /**
     * @return <i>Saving case metadata to file...</i>
     * @see Case
     */
    static String Case_progressMessage_savingCaseMetadata() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.savingCaseMetadata");
    }
    /**
     * @return <i>Setting up network communications...</i>
     * @see Case
     */
    static String Case_progressMessage_settingUpNetworkCommunications() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.settingUpNetworkCommunications");
    }
    /**
     * @return <i>Shutting down network communications...</i>
     * @see Case
     */
    static String Case_progressMessage_shuttingDownNetworkCommunications() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.shuttingDownNetworkCommunications");
    }
    /**
     * @return <i>Switching log directory...</i>
     * @see Case
     */
    static String Case_progressMessage_switchingLogDirectory() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.switchingLogDirectory");
    }
    /**
     * @return <i>Updating coordination service node data...</i>
     * @see Case
     */
    static String Case_progressMessage_updatingCaseNodeData() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.progressMessage.updatingCaseNodeData");
    }
    /**
     * @param serviceName serviceName
     * @return {@code serviceName}<i> Closing Case Resources</i>
     * @see Case
     */
    static String Case_serviceCloseResourcesProgressIndicator_title(Object serviceName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.serviceCloseResourcesProgressIndicator.title", serviceName);
    }
    /**
     * @param service_name service name
     * @return <i>Cancelling opening case resources by </i>{@code service_name}<i>...</i>
     * @see Case
     */
    static String Case_serviceOpenCaseResourcesProgressIndicator_cancellingMessage(Object service_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.serviceOpenCaseResourcesProgressIndicator.cancellingMessage", service_name);
    }
    /**
     * @param service_name service name
     * @return {@code service_name}<i> Opening Case Resources</i>
     * @see Case
     */
    static String Case_serviceOpenCaseResourcesProgressIndicator_title(Object service_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.serviceOpenCaseResourcesProgressIndicator.title", service_name);
    }
    /**
     * @param service_name service name
     * @return {@code service_name}<i> Error</i>
     * @see Case
     */
    static String Case_servicesException_notificationTitle(Object service_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.servicesException.notificationTitle", service_name);
    }
    /**
     * @param service_name service name
     * @param exception_message exception message
     * @return <i>Could not close case resources for </i>{@code service_name}<i> service: </i>{@code exception_message}
     * @see Case
     */
    static String Case_servicesException_serviceResourcesCloseError(Object service_name, Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Case.servicesException.serviceResourcesCloseError", service_name, exception_message);
    }
    /**
     * @return <i>Are you sure you want to remove the selected data source from the case?<br>Note that the case will be closed and re-opened during the removal.</i>
     * @see DeleteDataSourceAction
     */
    static String DeleteDataSourceAction_confirmationDialog_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DeleteDataSourceAction.confirmationDialog.message");
    }
    /**
     * @param exception_message exception message
     * @return <i>Failed to re-open the case:<br></i>{@code exception_message}<i><br>Please see the application log for details.</i>
     * @see DeleteDataSourceAction
     */
    static String DeleteDataSourceAction_exceptionMessage_couldNotReopenCase(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DeleteDataSourceAction.exceptionMessage.couldNotReopenCase", exception_message);
    }
    /**
     * @param exception_message exception message
     * @return <i>An error occurred while removing the data source:<br></i>{@code exception_message}<i><br>Please see the application log for details.</i>
     * @see DeleteDataSourceAction
     */
    static String DeleteDataSourceAction_exceptionMessage_dataSourceDeletionError(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DeleteDataSourceAction.exceptionMessage.dataSourceDeletionError", exception_message);
    }
    /**
     * @return <i>Data sources cannot be removed from a case when ingest is running.</i>
     * @see DeleteDataSourceAction
     */
    static String DeleteDataSourceAction_ingestRunningWarningDialog_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DeleteDataSourceAction.ingestRunningWarningDialog.message");
    }
    /**
     * @return <i>Remove Data Source</i>
     * @see DeleteDataSourceAction
     */
    static String DeleteDataSourceAction_name_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DeleteDataSourceAction.name.text");
    }
    /**
     * @return <i>Cancel</i>
     * @see EditOptionalCasePropertiesPanel
     */
    static String EditOptionalCasePropertiesPanel_cancelButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditOptionalCasePropertiesPanel.cancelButton.text");
    }
    /**
     * @return <i>Save</i>
     * @see EditOptionalCasePropertiesPanel
     */
    static String EditOptionalCasePropertiesPanel_saveButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditOptionalCasePropertiesPanel.saveButton.text");
    }
    /**
     * @return <i>Encase Images (*.e01)</i>
     * @see GeneralFilter
     */
    static String GeneralFilter_encaseImageDesc_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralFilter.encaseImageDesc.text");
    }
    /**
     * @return <i>Executables (*.exe)</i>
     * @see GeneralFilter
     */
    static String GeneralFilter_executableDesc_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralFilter.executableDesc.text");
    }
    /**
     * @return <i>Images (*.png, *.jpg, *.jpeg, *.gif, *.bmp)</i>
     * @see GeneralFilter
     */
    static String GeneralFilter_graphicImageDesc_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralFilter.graphicImageDesc.text");
    }
    /**
     * @return <i>Raw Images (*.img, *.dd, *.001, *.aa, *.raw, *.bin)</i>
     * @see GeneralFilter
     */
    static String GeneralFilter_rawImageDesc_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralFilter.rawImageDesc.text");
    }
    /**
     * @return <i>Virtual Machines (*.vmdk, *.vhd)</i>
     * @see GeneralFilter
     */
    static String GeneralFilter_virtualMachineImageDesc_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralFilter.virtualMachineImageDesc.text");
    }
    /**
     * @return <i>The selected file has extenson .001 but there is a .000 file in the sequence of raw images.<br>Should the .000 file be used as the start, instead of the selected .001 file?<br></i>
     * @see ImageFilePanel
     */
    static String ImageFilePanel_000_confirmationMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ImageFilePanel.000.confirmationMessage");
    }
    /**
     * @return <i>Module Error</i>
     * @see ImageFilePanel
     */
    static String ImageFilePanel_moduleErr() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ImageFilePanel.moduleErr");
    }
    /**
     * @return <i>A module caused an error listening to ImageFilePanel updates. See log to determine which module. Some data could be incomplete.<br></i>
     * @see ImageFilePanel
     */
    static String ImageFilePanel_moduleErr_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ImageFilePanel.moduleErr.msg");
    }
    /**
     * @return <i>Warning: Path to multi-user data source is on "C:" drive</i>
     * @see ImageFilePanel
     */
    static String ImageFilePanel_validatePanel_dataSourceOnCDriveError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ImageFilePanel.validatePanel.dataSourceOnCDriveError");
    }
    /**
     * @return <i>Invalid MD5 hash</i>
     * @see ImageFilePanel
     */
    static String ImageFilePanel_validatePanel_invalidMD5() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ImageFilePanel.validatePanel.invalidMD5");
    }
    /**
     * @return <i>Invalid SHA1 hash</i>
     * @see ImageFilePanel
     */
    static String ImageFilePanel_validatePanel_invalidSHA1() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ImageFilePanel.validatePanel.invalidSHA1");
    }
    /**
     * @return <i>Invalid SHA256 hash</i>
     * @see ImageFilePanel
     */
    static String ImageFilePanel_validatePanel_invalidSHA256() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ImageFilePanel.validatePanel.invalidSHA256");
    }
    /**
     * @return <i>End Time</i>
     * @see IngestJobInfoPanel
     */
    static String IngestJobInfoPanel_IngestJobTableModel_EndTime_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestJobInfoPanel.IngestJobTableModel.EndTime.header");
    }
    /**
     * @return <i>Ingest Status</i>
     * @see IngestJobInfoPanel
     */
    static String IngestJobInfoPanel_IngestJobTableModel_IngestStatus_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestJobInfoPanel.IngestJobTableModel.IngestStatus.header");
    }
    /**
     * @return <i>Start Time</i>
     * @see IngestJobInfoPanel
     */
    static String IngestJobInfoPanel_IngestJobTableModel_StartTime_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestJobInfoPanel.IngestJobTableModel.StartTime.header");
    }
    /**
     * @return <i>Module Name</i>
     * @see IngestJobInfoPanel
     */
    static String IngestJobInfoPanel_IngestModuleTableModel_ModuleName_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestJobInfoPanel.IngestModuleTableModel.ModuleName.header");
    }
    /**
     * @return <i>Module Version</i>
     * @see IngestJobInfoPanel
     */
    static String IngestJobInfoPanel_IngestModuleTableModel_ModuleVersion_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestJobInfoPanel.IngestModuleTableModel.ModuleVersion.header");
    }
    /**
     * @return <i>Failed to load ingest jobs.</i>
     * @see IngestJobInfoPanel
     */
    static String IngestJobInfoPanel_loadIngestJob_error_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestJobInfoPanel.loadIngestJob.error.text");
    }
    /**
     * @return <i>Load Failure</i>
     * @see IngestJobInfoPanel
     */
    static String IngestJobInfoPanel_loadIngestJob_error_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestJobInfoPanel.loadIngestJob.error.title");
    }
    /**
     * @return <i>LocalDiskPanel listener couldn't get the open case.</i>
     * @see LocalDiskPanel
     */
    static String LocalDiskPanel_errorMessage_noOpenCaseBody() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LocalDiskPanel.errorMessage.noOpenCaseBody");
    }
    /**
     * @return <i>No open case available</i>
     * @see LocalDiskPanel
     */
    static String LocalDiskPanel_errorMessage_noOpenCaseTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LocalDiskPanel.errorMessage.noOpenCaseTitle");
    }
    /**
     * @return <i>Error - directory does not exist</i>
     * @see LocalDiskPanel
     */
    static String LocalDiskPanel_imageWriterError_directoryNotExist() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LocalDiskPanel.imageWriterError.directoryNotExist");
    }
    /**
     * @return <i>Error - enter path for VHD</i>
     * @see LocalDiskPanel
     */
    static String LocalDiskPanel_imageWriterError_emptyPath() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LocalDiskPanel.imageWriterError.emptyPath");
    }
    /**
     * @return <i>Error - VHD path already exists</i>
     * @see LocalDiskPanel
     */
    static String LocalDiskPanel_imageWriterError_fileExists() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LocalDiskPanel.imageWriterError.fileExists");
    }
    /**
     * @return <i>Error - VHD path is a directory</i>
     * @see LocalDiskPanel
     */
    static String LocalDiskPanel_imageWriterError_isDirectory() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LocalDiskPanel.imageWriterError.isDirectory");
    }
    /**
     * @return <i>Unspecified</i>
     * @see LocalDiskPanel
     */
    static String LocalDiskPanel_localDiskMessage_unspecified() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LocalDiskPanel.localDiskMessage.unspecified");
    }
    /**
     * @return <i>A module caused an error listening to LocalDiskPanel updates. See log to determine which module. Some data could be incomplete.</i>
     * @see LocalDiskPanel
     */
    static String LocalDiskPanel_moduleErrorMessage_body() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LocalDiskPanel.moduleErrorMessage.body");
    }
    /**
     * @return <i>Module Error</i>
     * @see LocalDiskPanel
     */
    static String LocalDiskPanel_moduleErrorMessage_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LocalDiskPanel.moduleErrorMessage.title");
    }
    /**
     * @return <i>Disk Name</i>
     * @see LocalDiskSelectionDialog
     */
    static String LocalDiskSelectionDialog_columnName_diskName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LocalDiskSelectionDialog.columnName.diskName");
    }
    /**
     * @return <i>Disk Size</i>
     * @see LocalDiskSelectionDialog
     */
    static String LocalDiskSelectionDialog_columnName_diskSize() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LocalDiskSelectionDialog.columnName.diskSize");
    }
    /**
     * @return <i>Disks were not detected. On some systems it requires admin privileges (or "Run as administrator").</i>
     * @see LocalDiskSelectionDialog
     */
    static String LocalDiskSelectionDialog_errorMessage_disksNotDetected() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LocalDiskSelectionDialog.errorMessage.disksNotDetected");
    }
    /**
     * @return <i>Local drives were not detected. Auto-detection not supported on this OS  or admin privileges required</i>
     * @see LocalDiskSelectionDialog
     */
    static String LocalDiskSelectionDialog_errorMessage_drivesNotDetected() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LocalDiskSelectionDialog.errorMessage.drivesNotDetected");
    }
    /**
     * @return <i>Some disks were not detected. On some systems it requires admin privileges (or "Run as administrator").</i>
     * @see LocalDiskSelectionDialog
     */
    static String LocalDiskSelectionDialog_errorMessage_someDisksNotDetected() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LocalDiskSelectionDialog.errorMessage.someDisksNotDetected");
    }
    /**
     * @return <i>A module caused an error listening to LocalDiskPanel updates. See log to determine which module. Some data could be incomplete.</i>
     * @see LocalDiskSelectionDialog
     */
    static String LocalDiskSelectionDialog_moduleErrorMessage_body() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LocalDiskSelectionDialog.moduleErrorMessage.body");
    }
    /**
     * @return <i>Module Error</i>
     * @see LocalDiskSelectionDialog
     */
    static String LocalDiskSelectionDialog_moduleErrorMessage_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LocalDiskSelectionDialog.moduleErrorMessage.title");
    }
    /**
     * @return <i>Loading local disks...</i>
     * @see LocalDiskSelectionDialog
     */
    static String LocalDiskSelectionDialog_tableMessage_loading() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LocalDiskSelectionDialog.tableMessage.loading");
    }
    /**
     * @return <i>No Accessible Drives</i>
     * @see LocalDiskSelectionDialog
     */
    static String LocalDiskSelectionDialog_tableMessage_noDrives() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LocalDiskSelectionDialog.tableMessage.noDrives");
    }
    /**
     * @return <i>Logical Evidence Files (L01)</i>
     * @see LocalFilesDSProcessor
     */
    static String LocalFilesDSProcessor_logicalEvidenceFilter_desc() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LocalFilesDSProcessor.logicalEvidenceFilter.desc");
    }
    /**
     * @return <i>Warning: Path to multi-user data source is on "C:" drive</i>
     * @see LocalFilesPanel
     */
    static String LocalFilesPanel_pathValidation_dataSourceOnCDriveError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LocalFilesPanel.pathValidation.dataSourceOnCDriveError");
    }
    /**
     * @return <i>WARNING: Exception while gettting open case.</i>
     * @see LocalFilesPanel
     */
    static String LocalFilesPanel_pathValidation_getOpenCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LocalFilesPanel.pathValidation.getOpenCase");
    }
    /**
     * @return <i>A module caused an error listening to LogicalEvidenceFilePanel updates. See log to determine which module. Some data could be incomplete.</i>
     * @see LogicalEvidenceFilePanel
     */
    static String LogicalEvidenceFilePanel_moduleErr_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalEvidenceFilePanel.moduleErr.msg");
    }
    /**
     * @return <i>Module Error</i>
     * @see LogicalEvidenceFilePanel
     */
    static String LogicalEvidenceFilePanel_moduleErr_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalEvidenceFilePanel.moduleErr.name");
    }
    /**
     * @return <i>Warning: Path to multi-user data source is on "C:" drive</i>
     * @see LogicalEvidenceFilePanel
     */
    static String LogicalEvidenceFilePanel_pathValidation_dataSourceOnCDriveError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalEvidenceFilePanel.pathValidation.dataSourceOnCDriveError");
    }
    /**
     * @return <i>Warning: Exception while getting open case.</i>
     * @see LogicalEvidenceFilePanel
     */
    static String LogicalEvidenceFilePanel_pathValidation_getOpenCase_Error() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalEvidenceFilePanel.pathValidation.getOpenCase.Error");
    }
    /**
     * @return <i>Only files with the .l01 file extension are supported here.</i>
     * @see LogicalEvidenceFilePanel
     */
    static String LogicalEvidenceFilePanel_validatePanel_nonL01Error_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalEvidenceFilePanel.validatePanel.nonL01Error.text");
    }
    /**
     * @return <i>Logical evidence file (L01)</i>
     * @see LogicalFilesDspPanel
     */
    static String LogicalFilesDspPanel_subTypeComboBox_l01FileOption_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalFilesDspPanel.subTypeComboBox.l01FileOption.text");
    }
    /**
     * @return <i>Local files and folders</i>
     * @see LogicalFilesDspPanel
     */
    static String LogicalFilesDspPanel_subTypeComboBox_localFilesOption_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalFilesDspPanel.subTypeComboBox.localFilesOption.text");
    }
    /**
     * @param caseErrorMessage caseErrorMessage
     * @return <i>Failed to open case: </i>{@code caseErrorMessage}
     * @see OpenMultiUserCaseAction
     */
    static String OpenMultiUserCaseAction_caseOpeningErrorErrorMsg(Object caseErrorMessage) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OpenMultiUserCaseAction.caseOpeningErrorErrorMsg", caseErrorMessage);
    }
    /**
     * @return <i>Open Case</i>
     * @see OpenMultiUserCaseAction
     */
    static String OpenMultiUserCaseAction_menuItemText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OpenMultiUserCaseAction.menuItemText");
    }
    /**
     * @return <i>Open Multi-User Case</i>
     * @see OpenMultiUserCaseDialog
     */
    static String OpenMultiUserCaseDialog_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OpenMultiUserCaseDialog.title");
    }
    /**
     * @return <i>Manage Organizations</i>
     * @see OptionalCasePropertiesPanel
     */
    static String OptionalCasePropertiesPanel_bnNewOrganization_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OptionalCasePropertiesPanel.bnNewOrganization.text");
    }
    /**
     * @return <i>Name:</i>
     * @see OptionalCasePropertiesPanel
     */
    static String OptionalCasePropertiesPanel_caseDisplayNameLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OptionalCasePropertiesPanel.caseDisplayNameLabel.text");
    }
    /**
     * @return <i>Number:</i>
     * @see OptionalCasePropertiesPanel
     */
    static String OptionalCasePropertiesPanel_caseNumberLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OptionalCasePropertiesPanel.caseNumberLabel.text");
    }
    /**
     * @return <i>Case</i>
     * @see OptionalCasePropertiesPanel
     */
    static String OptionalCasePropertiesPanel_casePanel_border_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OptionalCasePropertiesPanel.casePanel.border.title");
    }
    /**
     * @return <i>No case name entered.</i>
     * @see OptionalCasePropertiesPanel
     */
    static String OptionalCasePropertiesPanel_errorDialog_emptyCaseNameMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OptionalCasePropertiesPanel.errorDialog.emptyCaseNameMessage");
    }
    /**
     * @return <i>Case names cannot include the following symbols: \, /, :, *, ?, ", &lt;, >, |</i>
     * @see OptionalCasePropertiesPanel
     */
    static String OptionalCasePropertiesPanel_errorDialog_invalidCaseNameMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OptionalCasePropertiesPanel.errorDialog.invalidCaseNameMessage");
    }
    /**
     * @return <i>Exception while getting open case.</i>
     * @see OptionalCasePropertiesPanel
     */
    static String OptionalCasePropertiesPanel_errorDialog_noOpenCase_errMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OptionalCasePropertiesPanel.errorDialog.noOpenCase.errMsg");
    }
    /**
     * @return <i>Name:</i>
     * @see OptionalCasePropertiesPanel
     */
    static String OptionalCasePropertiesPanel_examinerLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OptionalCasePropertiesPanel.examinerLabel.text");
    }
    /**
     * @return <i>Examiner</i>
     * @see OptionalCasePropertiesPanel
     */
    static String OptionalCasePropertiesPanel_examinerPanel_border_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OptionalCasePropertiesPanel.examinerPanel.border.title");
    }
    /**
     * @return <i>Email:</i>
     * @see OptionalCasePropertiesPanel
     */
    static String OptionalCasePropertiesPanel_lbExaminerEmailLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OptionalCasePropertiesPanel.lbExaminerEmailLabel.text");
    }
    /**
     * @return <i>Phone:</i>
     * @see OptionalCasePropertiesPanel
     */
    static String OptionalCasePropertiesPanel_lbExaminerPhoneLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OptionalCasePropertiesPanel.lbExaminerPhoneLabel.text");
    }
    /**
     * @return <i>Notes:</i>
     * @see OptionalCasePropertiesPanel
     */
    static String OptionalCasePropertiesPanel_lbNotesLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OptionalCasePropertiesPanel.lbNotesLabel.text");
    }
    /**
     * @return <i>Organization analysis is being done for:</i>
     * @see OptionalCasePropertiesPanel
     */
    static String OptionalCasePropertiesPanel_lbOrganizationNameLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OptionalCasePropertiesPanel.lbOrganizationNameLabel.text");
    }
    /**
     * @return <i>Email:</i>
     * @see OptionalCasePropertiesPanel
     */
    static String OptionalCasePropertiesPanel_lbPointOfContactEmailLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OptionalCasePropertiesPanel.lbPointOfContactEmailLabel.text");
    }
    /**
     * @return <i>Point of Contact:</i>
     * @see OptionalCasePropertiesPanel
     */
    static String OptionalCasePropertiesPanel_lbPointOfContactNameLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OptionalCasePropertiesPanel.lbPointOfContactNameLabel.text");
    }
    /**
     * @return <i>Phone:</i>
     * @see OptionalCasePropertiesPanel
     */
    static String OptionalCasePropertiesPanel_lbPointOfContactPhoneLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OptionalCasePropertiesPanel.lbPointOfContactPhoneLabel.text");
    }
    /**
     * @return <i>Organization</i>
     * @see OptionalCasePropertiesPanel
     */
    static String OptionalCasePropertiesPanel_orgainizationPanel_border_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OptionalCasePropertiesPanel.orgainizationPanel.border.title");
    }
    /**
     * @param case_name case name
     * @return <i>Case </i>{@code case_name}<i> no longer exists.</i>
     * @see OpenRecentCasePanel
     */
    static String RecentItems_openRecentCase_msgDlg_text(Object case_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RecentItems.openRecentCase.msgDlg.text", case_name);
    }
    /**
     * @return <i>Select Data Source Type</i>
     * @see AddImageWizardSelectDspPanel
     */
    static String SelectDataSourceProcessorPanel_name_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SelectDataSourceProcessorPanel.name.text");
    }
    /**
     * @param autFilePath autFilePath
     * @return <i>Unable to open previously open case with metadata file: </i>{@code autFilePath}
     * @see StartupWindowProvider
     */
    static String StartupWindowProvider_openCase_cantOpen(Object autFilePath) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "StartupWindowProvider.openCase.cantOpen", autFilePath);
    }
    /**
     * @param reOpenFilePath reOpenFilePath
     * @return <i>Unable to open or delete file containing path </i>{@code reOpenFilePath}<i> to previously open case. The previous case will not be opened.</i>
     * @see StartupWindowProvider
     */
    static String StartupWindowProvider_openCase_deleteOpenFailure(Object reOpenFilePath) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "StartupWindowProvider.openCase.deleteOpenFailure", reOpenFilePath);
    }
    /**
     * @param autFilePath autFilePath
     * @return <i>Unable to open previously open case because metadata file not found at: </i>{@code autFilePath}
     * @see StartupWindowProvider
     */
    static String StartupWindowProvider_openCase_noFile(Object autFilePath) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "StartupWindowProvider.openCase.noFile", autFilePath);
    }
    /**
     * @return <i>Portable case package (.zip, .zip.001)</i>
     * @see UnpackagePortableCaseDialog
     */
    static String UnpackagePortableCaseDialog_UnpackagePortableCaseDialog_extensions() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UnpackagePortableCaseDialog.UnpackagePortableCaseDialog.extensions");
    }
    /**
     * @return <i>Unpackage Portable Case</i>
     * @see UnpackagePortableCaseDialog
     */
    static String UnpackagePortableCaseDialog_title_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UnpackagePortableCaseDialog.title.text");
    }
    /**
     * @return <i>File extension must be .zip or .zip.001</i>
     * @see UnpackagePortableCaseDialog
     */
    static String UnpackagePortableCaseDialog_validatePaths_badExtension() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UnpackagePortableCaseDialog.validatePaths.badExtension");
    }
    /**
     * @param case_folder case folder
     * @return <i>Folder </i>{@code case_folder}<i> already exists</i>
     * @see UnpackagePortableCaseDialog
     */
    static String UnpackagePortableCaseDialog_validatePaths_caseFolderExists(Object case_folder) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UnpackagePortableCaseDialog.validatePaths.caseFolderExists", case_folder);
    }
    /**
     * @return <i>Selected path is not a file</i>
     * @see UnpackagePortableCaseDialog
     */
    static String UnpackagePortableCaseDialog_validatePaths_caseIsNotFile() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UnpackagePortableCaseDialog.validatePaths.caseIsNotFile");
    }
    /**
     * @return <i>File does not exist</i>
     * @see UnpackagePortableCaseDialog
     */
    static String UnpackagePortableCaseDialog_validatePaths_caseNotFound() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UnpackagePortableCaseDialog.validatePaths.caseNotFound");
    }
    /**
     * @return <i>Folder does not exist</i>
     * @see UnpackagePortableCaseDialog
     */
    static String UnpackagePortableCaseDialog_validatePaths_folderNotFound() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UnpackagePortableCaseDialog.validatePaths.folderNotFound");
    }
    /**
     * @return <i>Output location is not a directory</i>
     * @see UnpackagePortableCaseDialog
     */
    static String UnpackagePortableCaseDialog_validatePaths_notAFolder() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UnpackagePortableCaseDialog.validatePaths.notAFolder");
    }
    /**
     * @return <i>Successfully unpacked case</i>
     * @see UnpackagePortableCaseProgressDialog
     */
    static String UnpackagePortableCaseProgressDialog_propertyChange_success() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UnpackagePortableCaseProgressDialog.propertyChange.success");
    }
    /**
     * @return <i>Unpackage Portable Case Progress</i>
     * @see UnpackagePortableCaseProgressDialog
     */
    static String UnpackagePortableCaseProgressDialog_title_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UnpackagePortableCaseProgressDialog.title.text");
    }
    /**
     * @return <i>Unpackaging canceled by user</i>
     * @see UnpackagePortableCaseProgressDialog
     */
    static String UnpackageWorker_doInBackground_canceled() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UnpackageWorker.doInBackground.canceled");
    }
    /**
     * @return <i>Error unpackaging case</i>
     * @see UnpackagePortableCaseProgressDialog
     */
    static String UnpackageWorker_doInBackground_errorCompressingCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UnpackageWorker.doInBackground.errorCompressingCase");
    }
    /**
     * @return <i>Could not locate 7-Zip executable</i>
     * @see UnpackagePortableCaseProgressDialog
     */
    static String UnpackageWorker_doInBackground_errorFinding7zip() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UnpackageWorker.doInBackground.errorFinding7zip");
    }
    /**
     * @return <i>Case has been previously opened. Open it again?</i>
     * @see UnpackagePortableCaseProgressDialog
     */
    static String UnpackageWorker_doInBackground_previouslySeenCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UnpackageWorker.doInBackground.previouslySeenCase");
    }
    private Bundle() {}
}
