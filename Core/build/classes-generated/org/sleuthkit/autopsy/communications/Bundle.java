package org.sleuthkit.autopsy.communications;
/** Localizable strings for {@link org.sleuthkit.autopsy.communications}. */
class Bundle {
    /**
     * @return <i>Account</i>
     * @see AccountDeviceInstanceNode
     */
    static String AccountNode_accountName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AccountNode.accountName");
    }
    /**
     * @return <i>Type</i>
     * @see AccountDeviceInstanceNode
     */
    static String AccountNode_accountType() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AccountNode.accountType");
    }
    /**
     * @return <i>Device</i>
     * @see AccountDeviceInstanceNode
     */
    static String AccountNode_device() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AccountNode.device");
    }
    /**
     * @return <i>Items</i>
     * @see AccountDeviceInstanceNode
     */
    static String AccountNode_messageCount() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AccountNode.messageCount");
    }
    /**
     * @return <i>Communications</i>
     * @see OpenCommVisualizationToolAction
     */
    static String CTL_OpenCVTAction() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CTL_OpenCVTAction");
    }
    /**
     * @return <i> Communications Visualization</i>
     * @see CVTTopComponent
     */
    static String CVTTopComponent_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CVTTopComponent.name");
    }
    /**
     * @return <i>Communications</i>
     * @see OpenCommVisualizationToolAction
     */
    static String OpenCVTAction_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OpenCVTAction.displayName");
    }
    /**
     * @return <i>Add Selected Accounts to Visualization</i>
     * @see PinAccountsAction
     */
    static String PinAccountsAction_pluralText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PinAccountsAction.pluralText");
    }
    /**
     * @return <i>Add Selected Account to Visualization</i>
     * @see PinAccountsAction
     */
    static String PinAccountsAction_singularText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PinAccountsAction.singularText");
    }
    /**
     * @return <i>Visualize Only Selected Accounts</i>
     * @see ResetAndPinAccountsAction
     */
    static String ResetAndPinAccountsAction_pluralText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ResetAndPinAccountsAction.pluralText");
    }
    /**
     * @return <i>Visualize Only Selected Account</i>
     * @see ResetAndPinAccountsAction
     */
    static String ResetAndPinAccountsAction_singularText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ResetAndPinAccountsAction.singularText");
    }
    /**
     * @return <i>Remove Selected Accounts</i>
     * @see UnpinAccountsAction
     */
    static String UnpinAccountsAction_pluralText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UnpinAccountsAction.pluralText");
    }
    /**
     * @return <i>Remove Selected Account</i>
     * @see UnpinAccountsAction
     */
    static String UnpinAccountsAction_singularText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UnpinAccountsAction.singularText");
    }
    /**
     * @return <i>Problem painting visualization.</i>
     * @see VisualizationPanel
     */
    static String VisalizationPanel_paintingError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisalizationPanel.paintingError");
    }
    /**
     * @return <i>Open Report</i>
     * @see VisualizationPanel
     */
    static String VisualizationPane_DisplayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPane_DisplayName");
    }
    /**
     * @return <i>Open Report Failure</i>
     * @see VisualizationPanel
     */
    static String VisualizationPane_MessageBoxTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPane_MessageBoxTitle");
    }
    /**
     * @return <i>The report file no longer exists.</i>
     * @see VisualizationPanel
     */
    static String VisualizationPane_MissingReportFileMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPane_MissingReportFileMessage");
    }
    /**
     * @return <i>There is no associated editor for reports of this type or the associated application failed to launch.</i>
     * @see VisualizationPanel
     */
    static String VisualizationPane_NoAssociatedEditorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPane_NoAssociatedEditorMessage");
    }
    /**
     * @return <i>This platform (operating system) does not support opening a file in an editor this way.</i>
     * @see VisualizationPanel
     */
    static String VisualizationPane_NoOpenInEditorSupportMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPane_NoOpenInEditorSupportMessage");
    }
    /**
     * @return <i>Open Report</i>
     * @see VisualizationPanel
     */
    static String VisualizationPane_Open_Report() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPane_Open_Report");
    }
    /**
     * @return <i>Permission to open the report file was denied.</i>
     * @see VisualizationPanel
     */
    static String VisualizationPane_ReportFileOpenPermissionDeniedMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPane_ReportFileOpenPermissionDeniedMessage");
    }
    /**
     * @return <i>OK</i>
     * @see VisualizationPanel
     */
    static String VisualizationPane_Report_OK_Button() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPane_Report_OK_Button");
    }
    /**
     * @param _report_path  report path
     * @return <i>Report Successfully create at:<br></i>{@code _report_path}
     * @see VisualizationPanel
     */
    static String VisualizationPane_Report_Success(Object _report_path) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPane_Report_Success", _report_path);
    }
    /**
     * @param _default_name  default name
     * @return <i>Report name was empty. Press OK to accept default report name: </i>{@code _default_name}
     * @see VisualizationPanel
     */
    static String VisualizationPane_accept_defaultName(Object _default_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPane_accept_defaultName", _default_name);
    }
    /**
     * @return <i>Blank Report Name</i>
     * @see VisualizationPanel
     */
    static String VisualizationPane_blank_report_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPane_blank_report_title");
    }
    /**
     * @return <i>Enter name for the Communications Snapshot Report:</i>
     * @see VisualizationPanel
     */
    static String VisualizationPane_fileName_prompt() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPane_fileName_prompt");
    }
    /**
     * @param _report_name  report name
     * @return <i>Overwrite existing report?<br></i>{@code _report_name}
     * @see VisualizationPanel
     */
    static String VisualizationPane_overrite_exiting(Object _report_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPane_overrite_exiting", _report_name);
    }
    /**
     * @return <i>Communications Snapshot</i>
     * @see VisualizationPanel
     */
    static String VisualizationPane_reportName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPane_reportName");
    }
    /**
     * @return <i>Communications</i>
     * @see VisualizationPanel
     */
    static String VisualizationPanel_action_dialogs_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPanel_action_dialogs_title");
    }
    /**
     * @return <i>Snapshot Report</i>
     * @see VisualizationPanel
     */
    static String VisualizationPanel_action_name_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPanel_action_name_text");
    }
    /**
     * @return <i>Cancel</i>
     * @see VisualizationPanel
     */
    static String VisualizationPanel_cancelButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPanel.cancelButton.text");
    }
    /**
     * @return <i>Computing Layout</i>
     * @see VisualizationPanel
     */
    static String VisualizationPanel_computingLayout() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPanel.computingLayout");
    }
    /**
     * @param layout_name layout name
     * @return {@code layout_name}<i> layout failed with locked vertices. Unlock some vertices or try a different layout.</i>
     * @see VisualizationPanel
     */
    static String VisualizationPanel_layoutFailWithLockedVertices_text(Object layout_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPanel.layoutFailWithLockedVertices.text", layout_name);
    }
    /**
     * @param _layout_name  layout name
     * @return {@code _layout_name}<i> layout failed. Try a different layout.</i>
     * @see VisualizationPanel
     */
    static String VisualizationPanel_layoutFail_text(Object _layout_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPanel.layoutFail.text", _layout_name);
    }
    /**
     * @return <i>Lock Selected Accounts</i>
     * @see VisualizationPanel
     */
    static String VisualizationPanel_lockAction_pluralText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPanel.lockAction.pluralText");
    }
    /**
     * @return <i>Lock Selected Account</i>
     * @see VisualizationPanel
     */
    static String VisualizationPanel_lockAction_singularText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPanel.lockAction.singularText");
    }
    /**
     * @return <i>Communications</i>
     * @see VisualizationPanel
     */
    static String VisualizationPanel_module_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPanel_module_name");
    }
    /**
     * @return <i>Snapshot report not created. An error occurred during creation.</i>
     * @see VisualizationPanel
     */
    static String VisualizationPanel_snapshot_report_failure() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPanel_snapshot_report_failure");
    }
    /**
     * @return <i>Unlock Selected Accounts</i>
     * @see VisualizationPanel
     */
    static String VisualizationPanel_unlockAction_pluralText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPanel.unlockAction.pluralText");
    }
    /**
     * @return <i>Unlock Selected Account</i>
     * @see VisualizationPanel
     */
    static String VisualizationPanel_unlockAction_singularText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VisualizationPanel.unlockAction.singularText");
    }
    /**
     * @return <i>Apply</i>
     * @see FiltersPanel
     */
    static String applyText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "applyText");
    }
    /**
     * @return <i>Refresh Results</i>
     * @see FiltersPanel
     */
    static String refreshText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "refreshText");
    }
    private Bundle() {}
}
