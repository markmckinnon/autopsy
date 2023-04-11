package org.sleuthkit.autopsy.timeline.ui.listvew;
/** Localizable strings for {@link org.sleuthkit.autopsy.timeline.ui.listvew}. */
class Bundle {
    /**
     * @return <i>Error getting event by id.</i>
     * @see ListTimeline
     */
    static String EventRow_updateItem_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EventRow.updateItem.errorMessage");
    }
    /**
     * @return <i>Error getting event by id.</i>
     * @see ListTimeline
     */
    static String EventTableCell_updateItem_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EventTableCell.updateItem.errorMessage");
    }
    /**
     * @return <i>There was a problem getting the content for the selected event.</i>
     * @see ListTimeline
     */
    static String ListChart_errorMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ListChart.errorMsg");
    }
    /**
     * @param the_number_of_events the number of events
     * @return {@code the_number_of_events}<i> events</i>
     * @see ListTimeline
     */
    static String ListTimeline_eventCountLabel_text(Object the_number_of_events) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ListTimeline.eventCountLabel.text", the_number_of_events);
    }
    /**
     * @return <i>There was a problem getting the hash set names for the selected event.</i>
     * @see ListTimeline
     */
    static String ListTimeline_hashHitTooltip_error() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ListTimeline.hashHitTooltip.error");
    }
    /**
     * @param hash_set_names hash set names
     * @return <i>Hash Sets:<br></i>{@code hash_set_names}
     * @see ListTimeline
     */
    static String ListTimeline_hashHitTooltip_text(Object hash_set_names) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ListTimeline.hashHitTooltip.text", hash_set_names);
    }
    /**
     * @return <i>There was a problem getting the tag names for the selected event.</i>
     * @see ListTimeline
     */
    static String ListTimeline_taggedTooltip_error() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ListTimeline.taggedTooltip.error");
    }
    /**
     * @param tag_names tag names
     * @return <i>Tags:<br></i>{@code tag_names}
     * @see ListTimeline
     */
    static String ListTimeline_taggedTooltip_text(Object tag_names) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ListTimeline.taggedTooltip.text", tag_names);
    }
    /**
     * @return <i>Updating List View</i>
     * @see ListViewPane
     */
    static String ListViewPane_loggedTask_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ListViewPane.loggedTask.name");
    }
    /**
     * @return <i>Retrieving event data</i>
     * @see ListViewPane
     */
    static String ListViewPane_loggedTask_queryDb() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ListViewPane.loggedTask.queryDb");
    }
    /**
     * @return <i>Populating view</i>
     * @see ListViewPane
     */
    static String ListViewPane_loggedTask_updateUI() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ListViewPane.loggedTask.updateUI");
    }
    /**
     * @return <i>File Accessed ( A )</i>
     * @see ListTimeline
     */
    static String ListView_EventTypeCell_accessedTooltip() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ListView.EventTypeCell.accessedTooltip");
    }
    /**
     * @return <i>File Changed ( C )</i>
     * @see ListTimeline
     */
    static String ListView_EventTypeCell_changedTooltip() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ListView.EventTypeCell.changedTooltip");
    }
    /**
     * @return <i>File Created ( B, for Born )</i>
     * @see ListTimeline
     */
    static String ListView_EventTypeCell_createdTooltip() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ListView.EventTypeCell.createdTooltip");
    }
    /**
     * @return <i>File Modified ( M )</i>
     * @see ListTimeline
     */
    static String ListView_EventTypeCell_modifiedTooltip() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ListView.EventTypeCell.modifiedTooltip");
    }
    private Bundle() {}
}
