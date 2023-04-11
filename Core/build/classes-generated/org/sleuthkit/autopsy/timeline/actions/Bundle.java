package org.sleuthkit.autopsy.timeline.actions;
/** Localizable strings for {@link org.sleuthkit.autopsy.timeline.actions}. */
class Bundle {
    /**
     * @param datasource_name datasource name
     * @param datasource_id datasource id
     * @return {@code datasource_name}<i> (ID: </i>{@code datasource_id}<i>)</i>
     * @see AddManualEvent
     */
    static String AddManualEvent_EventCreationDialogPane_dataSourceStringConverter_template(Object datasource_name, Object datasource_id) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddManualEvent.EventCreationDialogPane.dataSourceStringConverter.template", datasource_name, datasource_id);
    }
    /**
     * @return <i>Error getting datasources in case.</i>
     * @see AddManualEvent
     */
    static String AddManualEvent_EventCreationDialogPane_initialize_dataSourcesError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddManualEvent.EventCreationDialogPane.initialize.dataSourcesError");
    }
    /**
     * @return <i>Failed to create artifact for event.</i>
     * @see AddManualEvent
     */
    static String AddManualEvent_createArtifactFailed() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddManualEvent.createArtifactFailed");
    }
    /**
     * @return <i>Manually add an event to the timeline.</i>
     * @see AddManualEvent
     */
    static String AddManualEvent_longText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddManualEvent.longText");
    }
    /**
     * @return <i>Failed to post artifact to blackboard.</i>
     * @see AddManualEvent
     */
    static String AddManualEvent_postArtifactFailed() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddManualEvent.postArtifactFailed");
    }
    /**
     * @return <i>Add Event</i>
     * @see AddManualEvent
     */
    static String AddManualEvent_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddManualEvent.text");
    }
    /**
     * @return <i>Invalid datetime</i>
     * @see AddManualEvent
     */
    static String AddManualEvent_validation_datetime() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddManualEvent.validation.datetime");
    }
    /**
     * @return <i>Description is required.</i>
     * @see AddManualEvent
     */
    static String AddManualEvent_validation_description() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddManualEvent.validation.description");
    }
    /**
     * @return <i>Invalid time zone</i>
     * @see AddManualEvent
     */
    static String AddManualEvent_validation_timezone() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddManualEvent.validation.timezone");
    }
    /**
     * @param action_accelerator_keys_ action accelerator keys 
     * @return <i>Back: </i>{@code action_accelerator_keys_}<i><br>Go back to the last view settings.</i>
     * @see Back
     */
    static String Back_longText(Object action_accelerator_keys_) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Back.longText", action_accelerator_keys_);
    }
    /**
     * @return <i>Back</i>
     * @see Back
     */
    static String Back_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Back.text");
    }
    /**
     * @param action_accelerator_keys_ action accelerator keys 
     * @return <i>Forward: </i>{@code action_accelerator_keys_}<i><br>Go forward to the next view settings.</i>
     * @see Forward
     */
    static String Forward_longText(Object action_accelerator_keys_) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Forward.longText", action_accelerator_keys_);
    }
    /**
     * @return <i>Forward</i>
     * @see Forward
     */
    static String Forward_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Forward.text");
    }
    /**
     * @return <i>Open Report</i>
     * @see SaveSnapshotAsReport
     */
    static String OpenReportAction_DisplayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OpenReportAction.DisplayName");
    }
    /**
     * @return <i>Open Report Failure</i>
     * @see SaveSnapshotAsReport
     */
    static String OpenReportAction_MessageBoxTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OpenReportAction.MessageBoxTitle");
    }
    /**
     * @return <i>The report file no longer exists.</i>
     * @see SaveSnapshotAsReport
     */
    static String OpenReportAction_MissingReportFileMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OpenReportAction.MissingReportFileMessage");
    }
    /**
     * @return <i>There is no associated editor for reports of this type or the associated application failed to launch.</i>
     * @see SaveSnapshotAsReport
     */
    static String OpenReportAction_NoAssociatedEditorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OpenReportAction.NoAssociatedEditorMessage");
    }
    /**
     * @return <i>This platform (operating system) does not support opening a file in an editor this way.</i>
     * @see SaveSnapshotAsReport
     */
    static String OpenReportAction_NoOpenInEditorSupportMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OpenReportAction.NoOpenInEditorSupportMessage");
    }
    /**
     * @return <i>Permission to open the report file was denied.</i>
     * @see SaveSnapshotAsReport
     */
    static String OpenReportAction_ReportFileOpenPermissionDeniedMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OpenReportAction.ReportFileOpenPermissionDeniedMessage");
    }
    /**
     * @return <i>Reset all filters</i>
     * @see ResetFilters
     */
    static String ResetFilters_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ResetFilters.text");
    }
    /**
     * @return <i>Reset all filters to their default state.</i>
     * @see ResetFilters
     */
    static String RestFilters_longText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RestFilters.longText");
    }
    /**
     * @param report_path report path
     * @return <i>Error writing report to disk at </i>{@code report_path}<i>.</i>
     * @see SaveSnapshotAsReport
     */
    static String SaveSnapShotAsReport_ErrorWritingReport(Object report_path) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SaveSnapShotAsReport.ErrorWritingReport", report_path);
    }
    /**
     * @return <i>Failed to add snaphot to case as a report.</i>
     * @see SaveSnapshotAsReport
     */
    static String SaveSnapShotAsReport_FailedToAddReport() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SaveSnapShotAsReport.FailedToAddReport");
    }
    /**
     * @return <i>OK</i>
     * @see SaveSnapshotAsReport
     */
    static String SaveSnapShotAsReport_OK_Button() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SaveSnapShotAsReport_OK_Button");
    }
    /**
     * @return <i>Open Report</i>
     * @see SaveSnapshotAsReport
     */
    static String SaveSnapShotAsReport_Open_Button() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SaveSnapShotAsReport_Open_Button");
    }
    /**
     * @param supplied_report_name supplied report name
     * @return <i>Failed to create report. Supplied report name has invalid characters: </i>{@code supplied_report_name}
     * @see SaveSnapshotAsReport
     */
    static String SaveSnapShotAsReport_Path_Failure_Report(Object supplied_report_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SaveSnapShotAsReport_Path_Failure_Report", supplied_report_name);
    }
    /**
     * @param report_file_path report file path
     * @return <i>Report saved at [</i>{@code report_file_path}<i>]</i>
     * @see SaveSnapshotAsReport
     */
    static String SaveSnapShotAsReport_ReportSavedAt(Object report_file_path) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SaveSnapShotAsReport.ReportSavedAt", report_file_path);
    }
    /**
     * @return <i>Report failed</i>
     * @see SaveSnapshotAsReport
     */
    static String SaveSnapShotAsReport_Report_Failed() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SaveSnapShotAsReport_Report_Failed");
    }
    /**
     * @return <i>Success</i>
     * @see SaveSnapshotAsReport
     */
    static String SaveSnapShotAsReport_Success() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SaveSnapShotAsReport.Success");
    }
    /**
     * @return <i>Timeline</i>
     * @see SaveSnapshotAsReport
     */
    static String SaveSnapShotAsReport_action_dialogs_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SaveSnapShotAsReport.action.dialogs.title");
    }
    /**
     * @return <i>Save a screen capture of the current view of the timeline as a report.</i>
     * @see SaveSnapshotAsReport
     */
    static String SaveSnapShotAsReport_action_longText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SaveSnapShotAsReport.action.longText");
    }
    /**
     * @return <i>Snapshot Report</i>
     * @see SaveSnapshotAsReport
     */
    static String SaveSnapShotAsReport_action_name_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SaveSnapShotAsReport.action.name.text");
    }
    /**
     * @return <i>A report with that name already exists.</i>
     * @see SaveSnapshotAsReport
     */
    static String SaveSnapShotAsReport_duplicateReportNameError_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SaveSnapShotAsReport.duplicateReportNameError.text");
    }
    /**
     * @return <i>Enter a report name for the Timeline Snapshot Report.</i>
     * @see SaveSnapshotAsReport
     */
    static String SaveSnapShotAsReport_reportName_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SaveSnapShotAsReport.reportName.header");
    }
    /**
     * @param generated_default_report_name generated default report name
     * @return <i>Leave empty for default report name:<br></i>{@code generated_default_report_name}<i>.</i>
     * @see SaveSnapshotAsReport
     */
    static String SaveSnapShotAsReport_reportName_prompt(Object generated_default_report_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SaveSnapShotAsReport.reportName.prompt", generated_default_report_name);
    }
    /**
     * @param report_location report location
     * @return <i>Snapshot report successfully created at location: <br><br> </i>{@code report_location}
     * @see SaveSnapshotAsReport
     */
    static String SaveSnapShotAsReport_success_message(Object report_location) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SaveSnapShotAsReport_success_message", report_location);
    }
    /**
     * @return <i>Timeline</i>
     * @see SaveSnapshotAsReport
     */
    static String Timeline_ModuleName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Timeline.ModuleName");
    }
    /**
     * @return <i>View Result in Timeline... </i>
     * @see ViewArtifactInTimelineAction
     */
    static String ViewArtifactInTimelineAction_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewArtifactInTimelineAction.displayName");
    }
    /**
     * @return <i>View File in Timeline... </i>
     * @see ViewFileInTimelineAction
     */
    static String ViewFileInTimelineAction_viewFile_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFileInTimelineAction.viewFile.displayName");
    }
    /**
     * @return <i>View Source File in Timeline... </i>
     * @see ViewFileInTimelineAction
     */
    static String ViewFileInTimelineAction_viewSourceFile_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFileInTimelineAction.viewSourceFile.displayName");
    }
    /**
     * @return <i>Zoom in</i>
     * @see ZoomIn
     */
    static String ZoomIn_action_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ZoomIn.action.text");
    }
    /**
     * @return <i>Error zooming in.</i>
     * @see ZoomIn
     */
    static String ZoomIn_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ZoomIn.errorMessage");
    }
    /**
     * @return <i>Zoom in to view about half as much time.</i>
     * @see ZoomIn
     */
    static String ZoomIn_longText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ZoomIn.longText");
    }
    /**
     * @return <i>Zoom out</i>
     * @see ZoomOut
     */
    static String ZoomOut_action_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ZoomOut.action.text");
    }
    /**
     * @return <i>Error getting spanning interval.</i>
     * @see ZoomOut
     */
    static String ZoomOut_disabledProperty_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ZoomOut.disabledProperty.errorMessage");
    }
    /**
     * @return <i>Error zooming out.</i>
     * @see ZoomOut
     */
    static String ZoomOut_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ZoomOut.errorMessage");
    }
    /**
     * @return <i>Zoom out to view about 50% more time.</i>
     * @see ZoomOut
     */
    static String ZoomOut_longText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ZoomOut.longText");
    }
    /**
     * @return <i>Zoom to events</i>
     * @see ZoomToEvents
     */
    static String ZoomToEvents_action_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ZoomToEvents.action.text");
    }
    /**
     * @return <i>Error getting spanning interval.</i>
     * @see ZoomToEvents
     */
    static String ZoomToEvents_disabledProperty_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ZoomToEvents.disabledProperty.errorMessage");
    }
    /**
     * @return <i>Zoom out to show the nearest events.</i>
     * @see ZoomToEvents
     */
    static String ZoomToEvents_longText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ZoomToEvents.longText");
    }
    private Bundle() {}
}
