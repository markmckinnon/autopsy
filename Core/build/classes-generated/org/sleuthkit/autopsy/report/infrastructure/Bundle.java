package org.sleuthkit.autopsy.report.infrastructure;
/** Localizable strings for {@link org.sleuthkit.autopsy.report.infrastructure}. */
class Bundle {
    /**
     * @return <i>Error loading interesting item set names</i>
     * @see PortableCaseInterestingItemsListPanel
     */
    static String PortableCaseInterestingItemsListPanel_error_errorLoadingTags() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseInterestingItemsListPanel.error.errorLoadingTags");
    }
    /**
     * @return <i>Error getting intesting item set names for case</i>
     * @see PortableCaseInterestingItemsListPanel
     */
    static String PortableCaseInterestingItemsListPanel_error_errorTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseInterestingItemsListPanel.error.errorTitle");
    }
    /**
     * @return <i>There is no case open</i>
     * @see PortableCaseInterestingItemsListPanel
     */
    static String PortableCaseInterestingItemsListPanel_error_noOpenCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseInterestingItemsListPanel.error.noOpenCase");
    }
    /**
     * @return <i>Error loading tags</i>
     * @see PortableCaseTagsListPanel
     */
    static String PortableCaseTagsListPanel_error_errorLoadingTags() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseTagsListPanel.error.errorLoadingTags");
    }
    /**
     * @return <i>Error getting tag names for case</i>
     * @see PortableCaseTagsListPanel
     */
    static String PortableCaseTagsListPanel_error_errorTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseTagsListPanel.error.errorTitle");
    }
    /**
     * @return <i>There is no case open</i>
     * @see PortableCaseTagsListPanel
     */
    static String PortableCaseTagsListPanel_error_noOpenCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseTagsListPanel.error.noOpenCase");
    }
    /**
     * @return <i>Comment</i>
     * @see TableReportGenerator
     */
    static String ReportGenerator_artTableColHdr_comment() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportGenerator.artTableColHdr.comment");
    }
    /**
     * @return <i>Failed to get result tags.</i>
     * @see TableReportGenerator
     */
    static String ReportGenerator_errList_failedGetBBArtifactTags() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportGenerator.errList.failedGetBBArtifactTags");
    }
    /**
     * @return <i>No open case available.</i>
     * @see TableReportGenerator
     */
    static String ReportGenerator_errList_noOpenCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportGenerator.errList.noOpenCase");
    }
    /**
     * @param report_module_name report module name
     * @return <i>Exception while running report module </i>{@code report_module_name}
     * @see ReportGenerator
     */
    static String ReportGenerator_error_exception(Object report_module_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportGenerator.error.exception", report_module_name);
    }
    /**
     * @param report_module_name report module name
     * @return <i>Invalid settings for report module </i>{@code report_module_name}
     * @see ReportGenerator
     */
    static String ReportGenerator_error_invalidSettings(Object report_module_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportGenerator.error.invalidSettings", report_module_name);
    }
    /**
     * @param report_module_name report module name
     * @return <i>Report module </i>{@code report_module_name}<i> not found</i>
     * @see ReportGenerator
     */
    static String ReportGenerator_error_moduleNotFound(Object report_module_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportGenerator.error.moduleNotFound", report_module_name);
    }
    /**
     * @param report_module_name report module name
     * @return <i>No file report settings for report module </i>{@code report_module_name}
     * @see ReportGenerator
     */
    static String ReportGenerator_error_noFileReportSettings(Object report_module_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportGenerator.error.noFileReportSettings", report_module_name);
    }
    /**
     * @return <i>No report modules found</i>
     * @see ReportGenerator
     */
    static String ReportGenerator_error_noReportModules() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportGenerator.error.noReportModules");
    }
    /**
     * @param report_module_name report module name
     * @return <i>No table report settings for report module </i>{@code report_module_name}
     * @see ReportGenerator
     */
    static String ReportGenerator_error_noTableReportSettings(Object report_module_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportGenerator.error.noTableReportSettings", report_module_name);
    }
    /**
     * @param report_configuration_name report configuration name
     * @return <i>Unable to load reporting configuration </i>{@code report_configuration_name}<i>.</i>
     * @see ReportGenerator
     */
    static String ReportGenerator_error_unableToLoadConfig(Object report_configuration_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportGenerator.error.unableToLoadConfig", report_configuration_name);
    }
    /**
     * @param report_module_name report module name
     * @return <i>Report module </i>{@code report_module_name}<i> has unsupported report module type</i>
     * @see ReportGenerator
     */
    static String ReportGenerator_error_unsupportedType(Object report_module_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportGenerator.error.unsupportedType", report_module_name);
    }
    /**
     * @return <i>User Name</i>
     * @see TableReportGenerator
     */
    static String ReportGenerator_tagTable_header_userName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportGenerator.tagTable.header.userName");
    }
    /**
     * @return <i>Report generation cancelled</i>
     * @see ReportProgressIndicator
     */
    static String ReportProgressIndicator_cancelledMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportProgressIndicator.cancelledMessage");
    }
    /**
     * @return <i>Report generation completed</i>
     * @see ReportProgressIndicator
     */
    static String ReportProgressIndicator_completedMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportProgressIndicator.completedMessage");
    }
    /**
     * @return <i>Report generation completed with errors</i>
     * @see ReportProgressIndicator
     */
    static String ReportProgressIndicator_completedWithErrorsMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportProgressIndicator.completedWithErrorsMessage");
    }
    /**
     * @return <i>Report generation started</i>
     * @see ReportProgressIndicator
     */
    static String ReportProgressIndicator_startMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportProgressIndicator.startMessage");
    }
    /**
     * @return <i>Report generation progress switched to determinate</i>
     * @see ReportProgressIndicator
     */
    static String ReportProgressIndicator_switchToDeterminateMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportProgressIndicator.switchToDeterminateMessage");
    }
    /**
     * @return <i>Report generation progress switched to indeterminate</i>
     * @see ReportProgressIndicator
     */
    static String ReportProgressIndicator_switchToIndeterminateMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportProgressIndicator.switchToIndeterminateMessage");
    }
    /**
     * @return <i>Are you sure you want to proceed with no selections?</i>
     * @see ReportWizardDataSourceSelectionPanel
     */
    static String ReportWizardDataSourceSelectionPanel_confirmEmptySelection() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportWizardDataSourceSelectionPanel.confirmEmptySelection");
    }
    /**
     * @return <i>Finish</i>
     * @see ReportWizardDataSourceSelectionPanel
     */
    static String ReportWizardDataSourceSelectionPanel_finishButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportWizardDataSourceSelectionPanel.finishButton.text");
    }
    /**
     * @return <i>Next</i>
     * @see ReportWizardDataSourceSelectionPanel
     */
    static String ReportWizardDataSourceSelectionPanel_nextButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportWizardDataSourceSelectionPanel.nextButton.text");
    }
    /**
     * @return <i>Select which data source(s) to include</i>
     * @see ReportWizardDataSourceSelectionPanel
     */
    static String ReportWizardDataSourceSelectionPanel_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportWizardDataSourceSelectionPanel.title");
    }
    /**
     * @return <i>Choose Portable Case settings</i>
     * @see ReportWizardPortableCaseOptionsVisualPanel
     */
    static String ReportWizardPortableCaseOptionsVisualPanel_getName_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportWizardPortableCaseOptionsVisualPanel.getName.title");
    }
    /**
     * @return <i>Review Status</i>
     * @see TableReportGenerator
     */
    static String TableReportGenerator_StatusColumn_Header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TableReportGenerator.StatusColumn.Header");
    }
    private Bundle() {}
}
