package org.sleuthkit.autopsy.timeline.explorernodes;
/** Localizable strings for {@link org.sleuthkit.autopsy.timeline.explorernodes}. */
class Bundle {
    /**
     * @return <i>Error getting actions</i>
     * @see EventNode
     */
    static String EventNode_getAction_errorTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EventNode.getAction.errorTitle");
    }
    /**
     * @return <i>There was a problem getting actions for the selected result.  The 'View File in Timeline' action will not be available.</i>
     * @see EventNode
     */
    static String EventNode_getAction_linkedFileMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EventNode.getAction.linkedFileMessage");
    }
    /**
     * @param maximum_number_of_events_to_display maximum number of events to display
     * @param the_number_of_events_that_is_too_many the number of events that is too many
     * @return <i>Too many events to display.  Maximum = </i>{@code maximum_number_of_events_to_display}<i>. But there are </i>{@code the_number_of_events_that_is_too_many}<i> to display.</i>
     * @see EventRootNode
     */
    static String EventRoodNode_tooManyNode_displayName(Object maximum_number_of_events_to_display, Object the_number_of_events_that_is_too_many) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EventRoodNode.tooManyNode.displayName", maximum_number_of_events_to_display, the_number_of_events_that_is_too_many);
    }
    /**
     * @return <i>Date/Time</i>
     * @see EventNode
     */
    static String NodeProperty_displayName_dateTime() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "NodeProperty.displayName.dateTime");
    }
    /**
     * @return <i>Description</i>
     * @see EventNode
     */
    static String NodeProperty_displayName_description() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "NodeProperty.displayName.description");
    }
    /**
     * @return <i>Event Type</i>
     * @see EventNode
     */
    static String NodeProperty_displayName_eventType() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "NodeProperty.displayName.eventType");
    }
    /**
     * @return <i>Icon</i>
     * @see EventNode
     */
    static String NodeProperty_displayName_icon() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "NodeProperty.displayName.icon");
    }
    /**
     * @return <i>Known</i>
     * @see EventNode
     */
    static String NodeProperty_displayName_known() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "NodeProperty.displayName.known");
    }
    private Bundle() {}
}
