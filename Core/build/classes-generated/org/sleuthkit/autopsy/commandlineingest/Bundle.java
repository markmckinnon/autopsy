package org.sleuthkit.autopsy.commandlineingest;
/** Localizable strings for {@link org.sleuthkit.autopsy.commandlineingest}. */
class Bundle {
    /**
     * @return <i>Report profile name was empty, no profile created.</i>
     * @see CommandLineIngestSettingsPanel
     */
    static String CommandLineIngestSettingPanel_empty_report_name_mgs() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommandLineIngestSettingPanel_empty_report_name_mgs");
    }
    /**
     * @return <i>Report profile name was already exists, no profile created.</i>
     * @see CommandLineIngestSettingsPanel
     */
    static String CommandLineIngestSettingPanel_existing_report_name_mgs() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommandLineIngestSettingPanel_existing_report_name_mgs");
    }
    /**
     * @return <i>Report profile name contained illegal characters, no profile created.</i>
     * @see CommandLineIngestSettingsPanel
     */
    static String CommandLineIngestSettingPanel_invalid_report_name_mgs() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommandLineIngestSettingPanel_invalid_report_name_mgs");
    }
    /**
     * @return <i>Default</i>
     * @see CommandLineIngestSettingsPanel
     */
    static String CommandListIngestSettingsPanel_Default_Report_DisplayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommandListIngestSettingsPanel_Default_Report_DisplayName");
    }
    /**
     * @return <i>Make new profile...</i>
     * @see CommandLineIngestSettingsPanel
     */
    static String CommandListIngestSettingsPanel_Make_Config() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommandListIngestSettingsPanel_Make_Config");
    }
    /**
     * @return <i>Please supply a report profile name (letters, digits, and underscore characters only):</i>
     * @see CommandLineIngestSettingsPanel
     */
    static String CommandListIngestSettingsPanel_Report_Name_Msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommandListIngestSettingsPanel_Report_Name_Msg");
    }
    private Bundle() {}
}
