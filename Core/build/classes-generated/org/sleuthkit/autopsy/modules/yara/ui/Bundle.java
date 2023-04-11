package org.sleuthkit.autopsy.modules.yara.ui;
/** Localizable strings for {@link org.sleuthkit.autopsy.modules.yara.ui}. */
class Bundle {
    /**
     * @return <i>Failed to open new window for rule set file.</i>
     * @see RuleSetDetailsPanel
     */
    static String RuleSetDetailsPanel_failed_to_open_folder_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RuleSetDetailsPanel_failed_to_open_folder_msg");
    }
    /**
     * @return <i>Open Error</i>
     * @see RuleSetDetailsPanel
     */
    static String RuleSetDetailsPanel_failed_to_open_folder_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RuleSetDetailsPanel_failed_to_open_folder_title");
    }
    /**
     * @return <i>YARA Options</i>
     * @see YaraGlobalSettingsPanel
     */
    static String YARA_Global_Settings_Panel_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "YARA_Global_Settings_Panel_Title");
    }
    /**
     * @param rule_set_name rule set name
     * @return <i>The folder for the selected YARA rule set, </i>{@code rule_set_name}<i>, no longer exists.</i>
     * @see YaraRuleSetOptionPanel
     */
    static String YaraRuleSetOptionPanel_RuleSet_Missing(Object rule_set_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "YaraRuleSetOptionPanel_RuleSet_Missing", rule_set_name);
    }
    /**
     * @return <i>Folder removed</i>
     * @see YaraRuleSetOptionPanel
     */
    static String YaraRuleSetOptionPanel_RuleSet_Missing_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "YaraRuleSetOptionPanel_RuleSet_Missing_title");
    }
    /**
     * @return <i>Rule set is invalid.<br>Rule set names must be non-empty string and unique.</i>
     * @see YaraRuleSetOptionPanel
     */
    static String YaraRuleSetOptionPanel_badName2_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "YaraRuleSetOptionPanel_badName2_msg");
    }
    /**
     * @param rule_set_name rule set name
     * @return <i>Rule set name </i>{@code rule_set_name}<i> already exists.<br>Rule set names must be unique.</i>
     * @see YaraRuleSetOptionPanel
     */
    static String YaraRuleSetOptionPanel_badName_msg(Object rule_set_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "YaraRuleSetOptionPanel_badName_msg", rule_set_name);
    }
    /**
     * @return <i>Create Rule Set</i>
     * @see YaraRuleSetOptionPanel
     */
    static String YaraRuleSetOptionPanel_badName_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "YaraRuleSetOptionPanel_badName_title");
    }
    /**
     * @return <i>Supply a new unique rule set name:</i>
     * @see YaraRuleSetOptionPanel
     */
    static String YaraRuleSetOptionPanel_new_rule_set_name_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "YaraRuleSetOptionPanel_new_rule_set_name_msg");
    }
    /**
     * @return <i>Rule Set Name</i>
     * @see YaraRuleSetOptionPanel
     */
    static String YaraRuleSetOptionPanel_new_rule_set_name_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "YaraRuleSetOptionPanel_new_rule_set_name_title");
    }
    /**
     * @param rule_set_name rule set name
     * @return <i>Unable to delete the selected YARA rule set </i>{@code rule_set_name}<i>.<br>Rule set may have already been removed.</i>
     * @see YaraRuleSetOptionPanel
     */
    static String YaraRuleSetOptionPanel_rule_set_delete(Object rule_set_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "YaraRuleSetOptionPanel_rule_set_delete", rule_set_name);
    }
    private Bundle() {}
}
