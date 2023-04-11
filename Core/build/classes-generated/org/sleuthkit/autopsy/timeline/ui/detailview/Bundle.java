package org.sleuthkit.autopsy.timeline.ui.detailview;
/** Localizable strings for {@link org.sleuthkit.autopsy.timeline.ui.detailview}. */
class Bundle {
    /**
     * @return <i>Collapse</i>
     * @see EventClusterNode
     */
    static String CollapseClusterAction_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CollapseClusterAction.text");
    }
    /**
     * @return <i>Advanced Layout Options</i>
     * @see DetailViewPane
     */
    static String DetailViewPane_advancedLayoutOptionsButtonLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DetailViewPane.advancedLayoutOptionsButtonLabel.text");
    }
    /**
     * @return <i>Band by Type</i>
     * @see DetailViewPane
     */
    static String DetailViewPane_bandByTypeBox_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DetailViewPane.bandByTypeBox.text");
    }
    /**
     * @return <i>Show Counts Only</i>
     * @see DetailViewPane
     */
    static String DetailViewPane_countsRadio_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DetailViewPane.countsRadio.text");
    }
    /**
     * @return <i>Hide Description</i>
     * @see DetailViewPane
     */
    static String DetailViewPane_hiddenRadio_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DetailViewPane.hiddenRadio.text");
    }
    /**
     * @return <i>Back (Cancel)</i>
     * @see DetailViewPane
     */
    static String DetailViewPane_loggedTask_backButton() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DetailViewPane.loggedTask.backButton");
    }
    /**
     * @return <i>Continue</i>
     * @see DetailViewPane
     */
    static String DetailViewPane_loggedTask_continueButton() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DetailViewPane.loggedTask.continueButton");
    }
    /**
     * @return <i>Updating Details View</i>
     * @see DetailViewPane
     */
    static String DetailViewPane_loggedTask_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DetailViewPane.loggedTask.name");
    }
    /**
     * @param number_of_events number of events
     * @return <i>You are about to show details for </i>{@code number_of_events}<i> events.  This might be very slow and could exhaust available memory.<br><br>Do you want to continue?</i>
     * @see DetailViewPane
     */
    static String DetailViewPane_loggedTask_prompt(Object number_of_events) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DetailViewPane.loggedTask.prompt", number_of_events);
    }
    /**
     * @return <i>Retrieving event data</i>
     * @see DetailViewPane
     */
    static String DetailViewPane_loggedTask_queryDb() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DetailViewPane.loggedTask.queryDb");
    }
    /**
     * @return <i>Populating view</i>
     * @see DetailViewPane
     */
    static String DetailViewPane_loggedTask_updateUI() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DetailViewPane.loggedTask.updateUI");
    }
    /**
     * @return <i>One Per Row</i>
     * @see DetailViewPane
     */
    static String DetailViewPane_oneEventPerRowBox_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DetailViewPane.oneEventPerRowBox.text");
    }
    /**
     * @return <i>Pinned Events</i>
     * @see DetailsChart
     */
    static String DetailViewPane_pinnedLaneLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DetailViewPane.pinnedLaneLabel.text");
    }
    /**
     * @return <i>All Events (Filtered)</i>
     * @see DetailViewPane
     */
    static String DetailViewPane_primaryLaneLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DetailViewPane.primaryLaneLabel.text");
    }
    /**
     * @return <i>Show Full Description</i>
     * @see DetailViewPane
     */
    static String DetailViewPane_showRadio_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DetailViewPane.showRadio.text");
    }
    /**
     * @return <i>Truncate Descriptions</i>
     * @see DetailViewPane
     */
    static String DetailViewPane_truncateAllBox_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DetailViewPane.truncateAllBox.text");
    }
    /**
     * @return <i>max description width (px):</i>
     * @see DetailViewPane
     */
    static String DetailViewPane_truncateSliderLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DetailViewPane.truncateSliderLabel.text");
    }
    /**
     * @return <i>loading...</i>
     * @see MultiEventNodeBase
     */
    static String EventBundleNodeBase_toolTip_loading() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EventBundleNodeBase.toolTip.loading");
    }
    /**
     * @return <i>Load sub events</i>
     * @see EventClusterNode
     */
    static String EventClusterNode_loggedTask_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EventClusterNode.loggedTask.name");
    }
    /**
     * @param hash_set_count_string hash set count string
     * @return <i><br><br>Hash Set Hits<br></i>{@code hash_set_count_string}
     * @see EventNodeBase
     */
    static String EventNodeBase_toolTip_hashSetHits(Object hash_set_count_string) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EventNodeBase.toolTip.hashSetHits", hash_set_count_string);
    }
    /**
     * @return <i>loading tooltip</i>
     * @see EventNodeBase
     */
    static String EventNodeBase_toolTip_loading2() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EventNodeBase.toolTip.loading2");
    }
    /**
     * @param tag_count_string tag count string
     * @return <i><br><br>Tags<br></i>{@code tag_count_string}
     * @see EventNodeBase
     */
    static String EventNodeBase_toolTip_tags(Object tag_count_string) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EventNodeBase.toolTip.tags", tag_count_string);
    }
    /**
     * @param counts counts
     * @param event_type event type
     * @param description description
     * @param start_date_time start date/time
     * @param end_date_time end date/time
     * @return {@code counts}<i> </i>{@code event_type}<i> events<br></i>{@code description}<i><br>between	</i>{@code start_date_time}<i><br>and   	</i>{@code end_date_time}
     * @see EventNodeBase
     */
    static String EventNodeBase_tooltip_text(Object counts, Object event_type, Object description, Object start_date_time, Object end_date_time) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EventNodeBase.tooltip.text", counts, event_type, description, start_date_time, end_date_time);
    }
    /**
     * @return <i>Expand</i>
     * @see EventClusterNode
     */
    static String ExpandClusterAction_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExpandClusterAction.text");
    }
    /**
     * @param date_time_at_guideline_position date/time at guideline position
     * @return {@code date_time_at_guideline_position}<i><br>Right-click to remove.<br>Drag to reposition.</i>
     * @see GuideLine
     */
    static String GuideLine_tooltip_text(Object date_time_at_guideline_position) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GuideLine.tooltip.text", date_time_at_guideline_position);
    }
    /**
     * @return <i>Hide this group from the details view.</i>
     * @see HideDescriptionAction
     */
    static String HideDescriptionAction_displayMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HideDescriptionAction.displayMsg");
    }
    /**
     * @return <i>Hide</i>
     * @see HideDescriptionAction
     */
    static String HideDescriptionAction_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HideDescriptionAction.displayName");
    }
    /**
     * @return <i>Pin</i>
     * @see EventNodeBase
     */
    static String PinEventAction_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PinEventAction.text");
    }
    /**
     * @return <i>Error adding pinned event to lane.</i>
     * @see PinnedEventsChartLane
     */
    static String PinnedChartLane_pinnedEventsListener_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PinnedChartLane.pinnedEventsListener.errorMessage");
    }
    /**
     * @return <i>Place Marker</i>
     * @see DetailsChart
     */
    static String PlaceMArkerAction_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlaceMArkerAction.name");
    }
    /**
     * @return <i>Error adding stripe to chart lane.</i>
     * @see PrimaryDetailsChartLane
     */
    static String PrimaryDetailsChartLane_stripeChangeListener_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PrimaryDetailsChartLane.stripeChangeListener.errorMessage");
    }
    /**
     * @return <i>Unpin</i>
     * @see EventNodeBase
     */
    static String UnPinEventAction_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UnPinEventAction.text");
    }
    /**
     * @return <i>Unhide</i>
     * @see UnhideDescriptionAction
     */
    static String UnhideDescriptionAction_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UnhideDescriptionAction.displayName");
    }
    private Bundle() {}
}
