package org.sleuthkit.autopsy.timeline;
/** Localizable strings for {@link org.sleuthkit.autopsy.timeline}. */
class Bundle {
    /**
     * @return <i>Error getting spanning interval.</i>
     * @see EventsModel
     */
    static String FilteredEventsModel_timeRangeProperty_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilteredEventsModel.timeRangeProperty.errorMessage");
    }
    /**
     * @return <i>Timeline</i>
     * @see EventsModel
     */
    static String FilteredEventsModel_timeRangeProperty_errorTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilteredEventsModel.timeRangeProperty.errorTitle");
    }
    /**
     * @return <i>Could not create timeline, there are no data sources.</i>
     * @see OpenTimelineAction
     */
    static String OpenTimeLineAction_msgdlg_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OpenTimeLineAction.msgdlg.text");
    }
    /**
     * @return <i>Timeline</i>
     * @see OpenTimelineAction
     */
    static String OpenTimelineAction_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OpenTimelineAction.displayName");
    }
    /**
     * @return <i>Failed to initialize timeline settings.</i>
     * @see OpenTimelineAction
     */
    static String OpenTimelineAction_settingsErrorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OpenTimelineAction.settingsErrorMessage");
    }
    /**
     * @return <i>Continue Without Updating</i>
     * @see PromptDialogManager
     */
    static String PrompDialogManager_buttonType_continueNoUpdate() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PrompDialogManager.buttonType.continueNoUpdate");
    }
    /**
     * @return <i>Continue</i>
     * @see PromptDialogManager
     */
    static String PrompDialogManager_buttonType_showTimeline() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PrompDialogManager.buttonType.showTimeline");
    }
    /**
     * @return <i>Update DB</i>
     * @see PromptDialogManager
     */
    static String PrompDialogManager_buttonType_update() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PrompDialogManager.buttonType.update");
    }
    /**
     * @return <i>Do you want to continue?</i>
     * @see PromptDialogManager
     */
    static String PromptDialogManager_confirmDuringIngest_contentText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PromptDialogManager.confirmDuringIngest.contentText");
    }
    /**
     * @return <i>Ingest is still going, and the Timeline may be incomplete.</i>
     * @see PromptDialogManager
     */
    static String PromptDialogManager_confirmDuringIngest_headerText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PromptDialogManager.confirmDuringIngest.headerText");
    }
    /**
     * @return <i>Populating Timeline Data</i>
     * @see PromptDialogManager
     */
    static String PromptDialogManager_progressDialog_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PromptDialogManager.progressDialog.title");
    }
    /**
     * @return <i>Details</i>
     * @see PromptDialogManager
     */
    static String PromptDialogManager_rebuildPrompt_details() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PromptDialogManager.rebuildPrompt.details");
    }
    /**
     * @return <i>The Timeline DB is incomplete and/or out of date.  Some events may be missing or inaccurate and some features may be unavailable.</i>
     * @see PromptDialogManager
     */
    static String PromptDialogManager_rebuildPrompt_headerText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PromptDialogManager.rebuildPrompt.headerText");
    }
    /**
     * @return <i>Timeline functionality is not available yet.  Timeline will be disabled. </i>
     * @see PromptDialogManager
     */
    static String PromptDialogManager_showTimeLineDisabledMessage_contentText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PromptDialogManager.showTimeLineDisabledMessage.contentText");
    }
    /**
     * @return 
     * @see PromptDialogManager
     */
    static String PromptDialogManager_showTimeLineDisabledMessage_headerText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PromptDialogManager.showTimeLineDisabledMessage.headerText");
    }
    /**
     * @return <i>There are too many files in the DB to ensure reasonable performance.  Timeline will be disabled. </i>
     * @see PromptDialogManager
     */
    static String PromptDialogManager_showTooManyFiles_contentText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PromptDialogManager.showTooManyFiles.contentText");
    }
    /**
     * @return 
     * @see PromptDialogManager
     */
    static String PromptDialogManager_showTooManyFiles_headerText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PromptDialogManager.showTooManyFiles.headerText");
    }
    /**
     * @return <i>The entered amount must only contain digits.</i>
     * @see ShowInTimelineDialog
     */
    static String ShowInTimelineDialog_amountValidator_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ShowInTimelineDialog.amountValidator.message");
    }
    /**
     * @return <i>View Result in Timeline.</i>
     * @see ShowInTimelineDialog
     */
    static String ShowInTimelineDialog_artifactTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ShowInTimelineDialog.artifactTitle");
    }
    /**
     * @return <i>You must select an event.</i>
     * @see ShowInTimelineDialog
     */
    static String ShowInTimelineDialog_eventSelectionValidator_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ShowInTimelineDialog.eventSelectionValidator.message");
    }
    /**
     * @param file_path file path
     * @return <i>View </i>{@code file_path}<i> in timeline.</i>
     * @see ShowInTimelineDialog
     */
    static String ShowInTimelineDialog_fileTitle(Object file_path) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ShowInTimelineDialog.fileTitle", file_path);
    }
    /**
     * @return <i>Show Timeline</i>
     * @see ShowInTimelineDialog
     */
    static String ShowInTimelineDialog_showTimelineButtonType_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ShowInTimelineDialog.showTimelineButtonType.text");
    }
    /**
     * @param start_of_date_range start of date range
     * @param end_of_date_range end of date range
     * @return {@code start_of_date_range}<i> to </i>{@code end_of_date_range}
     * @see TimeLineTopComponent
     */
    static String TimeLineResultView_startDateToEndDate_text(Object start_of_date_range, Object end_of_date_range) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimeLineResultView.startDateToEndDate.text", start_of_date_range, end_of_date_range);
    }
    /**
     * @return <i>Events</i>
     * @see TimeLineTopComponent
     */
    static String TimeLineTopComponent_eventsTab_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimeLineTopComponent.eventsTab.name");
    }
    /**
     * @return <i>Filters</i>
     * @see TimeLineTopComponent
     */
    static String TimeLineTopComponent_filterTab_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimeLineTopComponent.filterTab.name");
    }
    /**
     * @return <i>Do you want to update the events database now?</i>
     * @see TimeLineController
     */
    static String TimeLinecontroller_updateNowQuestion() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimeLinecontroller.updateNowQuestion");
    }
    /**
     * @return <i>There was a problem getting the content for the selected event.</i>
     * @see TimeLineTopComponent
     */
    static String TimelineTopComponent_selectedEventListener_errorMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimelineTopComponent.selectedEventListener.errorMsg");
    }
    /**
     * @return <i> Timeline</i>
     * @see TimeLineController
     */
    static String Timeline_dialogs_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Timeline.dialogs.title");
    }
    /**
     * @return <i> This Case was created with an older version of Autopsy.<br>The Timeline with not show events from data sources added with the older version of Autopsy</i>
     * @see TimeLineTopComponent
     */
    static String Timeline_old_version() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Timeline.old.version");
    }
    private Bundle() {}
}
