package org.sleuthkit.autopsy.ingest.runIngestModuleWizard;
/** Localizable strings for {@link org.sleuthkit.autopsy.ingest.runIngestModuleWizard}. */
class Bundle {
    /**
     * @return <i>Configure Ingest Modules</i>
     * @see IngestModulesConfigWizardPanel
     */
    static String IngestModulesConfigWizardPanel_name_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestModulesConfigWizardPanel.name.text");
    }
    /**
     * @return <i>configure individual module settings in next step of wizard</i>
     * @see IngestProfileSelectionPanel
     */
    static String IngestProfileSelectionPanel_customSettings_description() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestProfileSelectionPanel.customSettings.description");
    }
    /**
     * @return <i>Custom Settings</i>
     * @see IngestProfileSelectionPanel
     */
    static String IngestProfileSelectionPanel_customSettings_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestProfileSelectionPanel.customSettings.name");
    }
    /**
     * @return <i>Ingest Profile Selection</i>
     * @see IngestProfileSelectionWizardPanel
     */
    static String IngestProfileWizardPanel_panelName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestProfileWizardPanel.panelName");
    }
    /**
     * @return <i>Error querying the case database for the selected item.</i>
     * @see RunIngestModulesAction
     */
    static String RunIngestModulesAction_actionPerformed_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RunIngestModulesAction.actionPerformed.errorMessage");
    }
    /**
     * @return <i>Run Ingest Modules</i>
     * @see RunIngestModulesAction
     */
    static String RunIngestModulesAction_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RunIngestModulesAction.name");
    }
    private Bundle() {}
}
