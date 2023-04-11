package org.sleuthkit.autopsy.ingest;
/** Localizable strings for {@link org.sleuthkit.autopsy.ingest}. */
class Bundle {
    /**
     * @return <i>Run Ingest</i>
     * @see RunIngestAction
     */
    static String CTL_RunIngestAction() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CTL_RunIngestAction");
    }
    /**
     * @return <i>Saving Results</i>
     * @see FileIngestPipeline
     */
    static String FileIngestPipeline_SaveResults_Activity() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileIngestPipeline_SaveResults_Activity");
    }
    /**
     * @param tier_number tier number
     * @param job_state_modifer job state modifer
     * @return <i>Tier </i>{@code tier_number}<i> </i>{@code job_state_modifer}
     * @see IngestJobExecutor
     */
    static String IngestJobExecutor_progress_snapshot_currentTier(Object tier_number, Object job_state_modifer) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestJobExecutor_progress_snapshot_currentTier", tier_number, job_state_modifer);
    }
    /**
     * @return <i>shut down</i>
     * @see IngestJobExecutor
     */
    static String IngestJobExecutor_progress_snapshot_currentTier_shutDown_modifier() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestJobExecutor_progress_snapshot_currentTier_shutDown_modifier");
    }
    /**
     * @return <i>A previous version of this ingest module has been run before on this data source.</i>
     * @see IngestJobSettingsPanel
     */
    static String IngestJobSettingsPanel_IngestModulesTableRenderer_info_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestJobSettingsPanel.IngestModulesTableRenderer.info.message");
    }
    /**
     * @return <i>This ingest module has been run before on this data source.</i>
     * @see IngestJobSettingsPanel
     */
    static String IngestJobSettingsPanel_IngestModulesTableRenderer_warning_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestJobSettingsPanel.IngestModulesTableRenderer.warning.message");
    }
    /**
     * @return <i>The selected module has no per-run settings.</i>
     * @see IngestJobSettingsPanel
     */
    static String IngestJobSettingsPanel_noPerRunSettings() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestJobSettingsPanel.noPerRunSettings");
    }
    /**
     * @return <i>Ingest History</i>
     * @see IngestJobSettingsPanel
     */
    static String IngestJobSettingsPanel_pastJobsButton_action_frame_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestJobSettingsPanel.pastJobsButton.action.frame.title");
    }
    /**
     * @param data_source_name data source name
     * @return <i>Analyzing analysis results from </i>{@code data_source_name}
     * @see IngestJobExecutor
     */
    static String IngestJob_progress_analysisResultIngest_displayName(Object data_source_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestJob_progress_analysisResultIngest_displayName", data_source_name);
    }
    /**
     * @return <i>Errors:</i>
     * @see IngestManager
     */
    static String IngestManager_startupErr_dlgErrorList() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestManager.startupErr.dlgErrorList");
    }
    /**
     * @return <i>Unable to start up one or more ingest modules, ingest cancelled.</i>
     * @see IngestManager
     */
    static String IngestManager_startupErr_dlgMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestManager.startupErr.dlgMsg");
    }
    /**
     * @return <i>Please disable the failed modules or fix the errors before restarting ingest.</i>
     * @see IngestManager
     */
    static String IngestManager_startupErr_dlgSolution() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestManager.startupErr.dlgSolution");
    }
    /**
     * @return <i>Ingest Module Startup Failure</i>
     * @see IngestManager
     */
    static String IngestManager_startupErr_dlgTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestManager.startupErr.dlgTitle");
    }
    /**
     * @return <i>File Filters</i>
     * @see IngestOptionsPanel
     */
    static String IngestOptionsPanel_fileFiltersTab_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestOptionsPanel.fileFiltersTab.text");
    }
    /**
     * @return <i>Settings for creating and editing ingest file filters.</i>
     * @see IngestOptionsPanel
     */
    static String IngestOptionsPanel_fileFiltersTab_toolTipText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestOptionsPanel.fileFiltersTab.toolTipText");
    }
    /**
     * @return <i>Profiles</i>
     * @see IngestOptionsPanel
     */
    static String IngestOptionsPanel_profilesTab_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestOptionsPanel.profilesTab.text");
    }
    /**
     * @return <i>Settings for creating and editing profiles.</i>
     * @see IngestOptionsPanel
     */
    static String IngestOptionsPanel_profilesTab_toolTipText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestOptionsPanel.profilesTab.toolTipText");
    }
    /**
     * @return <i>Settings</i>
     * @see IngestOptionsPanel
     */
    static String IngestOptionsPanel_settingsTab_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestOptionsPanel.settingsTab.text");
    }
    /**
     * @return <i>Settings regarding resources available to ingest.</i>
     * @see IngestOptionsPanel
     */
    static String IngestOptionsPanel_settingsTab_toolTipText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestOptionsPanel.settingsTab.toolTipText");
    }
    /**
     * @return <i>Profile name contains an illegal character. Only <br>letters, digits, and underscore characters are allowed.</i>
     * @see ProfilePanel
     */
    static String ProfilePanel_messages_profileNameContainsIllegalCharacter() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ProfilePanel.messages.profileNameContainsIllegalCharacter");
    }
    /**
     * @return <i>Ingest profile must be named.</i>
     * @see ProfilePanel
     */
    static String ProfilePanel_messages_profilesMustBeNamed() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ProfilePanel.messages.profilesMustBeNamed");
    }
    /**
     * @return <i>NewEmptyProfile</i>
     * @see ProfilePanel
     */
    static String ProfilePanel_newProfileText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ProfilePanel.newProfileText");
    }
    /**
     * @return <i>Description:</i>
     * @see ProfilePanel
     */
    static String ProfilePanel_profileDescLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ProfilePanel.profileDescLabel.text");
    }
    /**
     * @return <i>Profile Name:</i>
     * @see ProfilePanel
     */
    static String ProfilePanel_profileNameLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ProfilePanel.profileNameLabel.text");
    }
    /**
     * @return <i>Profile</i>
     * @see ProfilePanel
     */
    static String ProfilePanel_title_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ProfilePanel.title.text");
    }
    /**
     * @return <i>Delete Profile</i>
     * @see ProfileSettingsPanel
     */
    static String ProfileSettingsPanel_deleteProfileButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ProfileSettingsPanel.deleteProfileButton.text");
    }
    /**
     * @param profile_name profile name
     * @return <i>Profile with name </i>{@code profile_name}<i> already exists.</i>
     * @see ProfileSettingsPanel
     */
    static String ProfileSettingsPanel_doFileSetsDialog_duplicateProfile_text(Object profile_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ProfileSettingsPanel.doFileSetsDialog.duplicateProfile.text", profile_name);
    }
    /**
     * @return <i>Edit Profile</i>
     * @see ProfileSettingsPanel
     */
    static String ProfileSettingsPanel_editProfileButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ProfileSettingsPanel.editProfileButton.text");
    }
    /**
     * @return <i>Filter:</i>
     * @see ProfileSettingsPanel
     */
    static String ProfileSettingsPanel_filterNameLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ProfileSettingsPanel.filterNameLabel.text");
    }
    /**
     * @return <i>An Ingest Profile runs a preconfigured set of ingest modules on some or all of the files in a data source. Create a profile if you frequently run the same set of modules on a subset of the files.</i>
     * @see ProfileSettingsPanel
     */
    static String ProfileSettingsPanel_infoTextArea_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ProfileSettingsPanel.infoTextArea.text");
    }
    /**
     * @return <i>Failed to load file ingest filter</i>
     * @see ProfileSettingsPanel
     */
    static String ProfileSettingsPanel_messages_filterLoadFailed() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ProfileSettingsPanel.messages.filterLoadFailed");
    }
    /**
     * @return <i>New Profile</i>
     * @see ProfileSettingsPanel
     */
    static String ProfileSettingsPanel_newProfileButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ProfileSettingsPanel.newProfileButton.text");
    }
    /**
     * @return <i>Profile Description:</i>
     * @see ProfileSettingsPanel
     */
    static String ProfileSettingsPanel_profileDescLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ProfileSettingsPanel.profileDescLabel.text");
    }
    /**
     * @return <i>Profiles:</i>
     * @see ProfileSettingsPanel
     */
    static String ProfileSettingsPanel_profileListLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ProfileSettingsPanel.profileListLabel.text");
    }
    /**
     * @return <i>Selected Ingest Modules:</i>
     * @see ProfileSettingsPanel
     */
    static String ProfileSettingsPanel_selectedModulesLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ProfileSettingsPanel.selectedModulesLabel.text");
    }
    /**
     * @return <i>Profile Settings</i>
     * @see ProfileSettingsPanel
     */
    static String ProfileSettingsPanel_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ProfileSettingsPanel.title");
    }
    private Bundle() {}
}
