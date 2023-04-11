package org.sleuthkit.autopsy.timeline.ui.filtering;
/** Localizable strings for {@link org.sleuthkit.autopsy.timeline.ui.filtering}. */
class Bundle {
    /**
     * @return <i>Hidden Descriptions</i>
     * @see FilterSetPanel
     */
    static String FilsetSetPanel_hiddenDescriptionsPane_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilsetSetPanel.hiddenDescriptionsPane.displayName");
    }
    /**
     * @return <i>(Re)Apply filters</i>
     * @see FilterSetPanel
     */
    static String FilterSetPanel_applyButton_longText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilterSetPanel.applyButton.longText");
    }
    /**
     * @return <i>Apply</i>
     * @see FilterSetPanel
     */
    static String FilterSetPanel_applyButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilterSetPanel.applyButton.text");
    }
    /**
     * @return <i>Reset</i>
     * @see FilterSetPanel
     */
    static String FilterSetPanel_defaultButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilterSetPanel.defaultButton.text");
    }
    /**
     * @return <i>Remove from list</i>
     * @see FilterSetPanel
     */
    static String FilterSetPanel_hiddenDescriptionsListView_remove() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilterSetPanel.hiddenDescriptionsListView.remove");
    }
    /**
     * @return <i>Unhide and remove from list</i>
     * @see FilterSetPanel
     */
    static String FilterSetPanel_hiddenDescriptionsListView_unhideAndRemove() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilterSetPanel.hiddenDescriptionsListView.unhideAndRemove");
    }
    /**
     * @return <i>all</i>
     * @see FilterTreeTableRow
     */
    static String Timeline_ui_filtering_menuItem_all() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Timeline.ui.filtering.menuItem.all");
    }
    /**
     * @return <i>none</i>
     * @see FilterTreeTableRow
     */
    static String Timeline_ui_filtering_menuItem_none() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Timeline.ui.filtering.menuItem.none");
    }
    /**
     * @return <i>only</i>
     * @see FilterTreeTableRow
     */
    static String Timeline_ui_filtering_menuItem_only() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Timeline.ui.filtering.menuItem.only");
    }
    /**
     * @return <i>others</i>
     * @see FilterTreeTableRow
     */
    static String Timeline_ui_filtering_menuItem_others() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Timeline.ui.filtering.menuItem.others");
    }
    /**
     * @return <i>select</i>
     * @see FilterTreeTableRow
     */
    static String Timeline_ui_filtering_menuItem_select() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Timeline.ui.filtering.menuItem.select");
    }
    /**
     * @return <i>enter filter string</i>
     * @see LegendCell
     */
    static String Timeline_ui_filtering_promptText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Timeline.ui.filtering.promptText");
    }
    private Bundle() {}
}
