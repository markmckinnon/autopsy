package org.sleuthkit.autopsy.timeline.ui.countsview;
/** Localizable strings for {@link org.sleuthkit.autopsy.timeline.ui.countsview}. */
class Bundle {
    /**
     * @return <i>Error selecting time and type.</i>
     * @see EventCountsChart
     */
    static String BarClickHandler_selectTimeAndType_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "BarClickHandler.selectTimeAndType.errorMessage");
    }
    /**
     * @return <i>Error zooming in.</i>
     * @see EventCountsChart
     */
    static String BarClickHandler_zoomIn_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "BarClickHandler_zoomIn_errorMessage");
    }
    /**
     * @return <i>There is no temporal resolution smaller than Seconds.<br>Would you like to switch to the Details view instead?</i>
     * @see EventCountsChart
     */
    static String CountsViewPane_detailSwitchMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CountsViewPane.detailSwitchMessage");
    }
    /**
     * @return <i>"Switch to Details View?</i>
     * @see EventCountsChart
     */
    static String CountsViewPane_detailSwitchTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CountsViewPane.detailSwitchTitle");
    }
    /**
     * @return <i>Linear</i>
     * @see CountsViewPane
     */
    static String CountsViewPane_linearRadio_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CountsViewPane.linearRadio.text");
    }
    /**
     * @return <i>Logarithmic</i>
     * @see CountsViewPane
     */
    static String CountsViewPane_logRadio_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CountsViewPane.logRadio.text");
    }
    /**
     * @return <i>Updating Counts View</i>
     * @see CountsViewPane
     */
    static String CountsViewPane_loggedTask_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CountsViewPane.loggedTask.name");
    }
    /**
     * @return <i>Populating view</i>
     * @see CountsViewPane
     */
    static String CountsViewPane_loggedTask_updatingCounts() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CountsViewPane.loggedTask.updatingCounts");
    }
    /**
     * @param scale_name scale name
     * @return <i>Number of Events (</i>{@code scale_name}<i>)</i>
     * @see CountsViewPane
     */
    static String CountsViewPane_numberOfEvents(Object scale_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CountsViewPane.numberOfEvents", scale_name);
    }
    /**
     * @return <i>The linear scale is good for many use cases.  When this scale is selected, the height of the bars represents the counts in a linear, one-to-one fashion, and the y-axis is labeled with values. When the range of values is very large, time periods with low counts may have a bar that is too small to see.  To help the user detect this, the labels for date ranges with events are bold.  To see bars that are too small, there are three options:  adjust the window size so that the timeline has more vertical space, adjust the time range shown so that time periods with larger bars are excluded, or adjust the scale setting to logarithmic.</i>
     * @see CountsViewPane
     */
    static String CountsViewPane_scaleHelpLinear() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CountsViewPane.scaleHelpLinear");
    }
    /**
     * @return <i>The logarithmic scale represents the number of events in a non-linear way that compresses the difference between large and small numbers. Note that even with the logarithmic scale, an extremely large difference in counts may still produce bars too small to see.  In this case the only option may be to filter events to reduce the difference in counts.  NOTE: Because the logarithmic scale is applied to each event type separately, the meaning of the height of the combined bar is not intuitive, and to emphasize this, no labels are shown on the y-axis with the logarithmic scale. The logarithmic scale should be used to quickly compare the counts </i>
     * @see CountsViewPane
     */
    static String CountsViewPane_scaleHelpLog() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CountsViewPane.scaleHelpLog");
    }
    /**
     * @return <i>across time within a type, or across types for one time period, but not both.</i>
     * @see CountsViewPane
     */
    static String CountsViewPane_scaleHelpLog2() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CountsViewPane.scaleHelpLog2");
    }
    /**
     * @return <i> The actual counts (available in tooltips or the result viewer) should be used for absolute comparisons.  Use the logarithmic scale with care.</i>
     * @see CountsViewPane
     */
    static String CountsViewPane_scaleHelpLog3() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CountsViewPane.scaleHelpLog3");
    }
    /**
     * @return <i>Scales:   </i>
     * @see CountsViewPane
     */
    static String CountsViewPane_scaleHelp_label_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CountsViewPane.scaleHelp.label.text");
    }
    /**
     * @return <i>Scale:</i>
     * @see CountsViewPane
     */
    static String CountsViewPane_scaleLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CountsViewPane.scaleLabel.text");
    }
    /**
     * @param count count
     * @param event_type_displayname event type displayname
     * @param start_date_time start date time
     * @param end_date_time end date time
     * @return {@code count}<i> </i>{@code event_type_displayname}<i> events<br>between </i>{@code start_date_time}<i><br>and     </i>{@code end_date_time}
     * @see EventCountsChart
     */
    static String CountsViewPane_tooltip_text(Object count, Object event_type_displayname, Object start_date_time, Object end_date_time) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CountsViewPane.tooltip.text", count, event_type_displayname, start_date_time, end_date_time);
    }
    /**
     * @return <i>Linear</i>
     * @see CountsViewPane
     */
    static String ScaleType_Linear() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ScaleType.Linear");
    }
    /**
     * @return <i>Logarithmic</i>
     * @see CountsViewPane
     */
    static String ScaleType_Logarithmic() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ScaleType.Logarithmic");
    }
    /**
     * @return <i>Error selecting interval.</i>
     * @see EventCountsChart
     */
    static String SelectIntervalAction_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SelectIntervalAction.errorMessage");
    }
    /**
     * @return <i>Error selecting interval and type.</i>
     * @see EventCountsChart
     */
    static String SelectIntervalAndTypeAction_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SelectIntervalAndTypeAction.errorMessage");
    }
    /**
     * @return <i>Error selecting type.</i>
     * @see EventCountsChart
     */
    static String SelectTypeAction_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SelectTypeAction.errorMessage");
    }
    /**
     * @return <i>Select Event Type</i>
     * @see EventCountsChart
     */
    static String Timeline_ui_countsview_menuItem_selectEventType() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Timeline.ui.countsview.menuItem.selectEventType");
    }
    /**
     * @return <i>Select Time Range</i>
     * @see EventCountsChart
     */
    static String Timeline_ui_countsview_menuItem_selectTimeRange() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Timeline.ui.countsview.menuItem.selectTimeRange");
    }
    /**
     * @return <i>Select Time and Type</i>
     * @see EventCountsChart
     */
    static String Timeline_ui_countsview_menuItem_selectTimeandType() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Timeline.ui.countsview.menuItem.selectTimeandType");
    }
    /**
     * @return <i>Zoom into Time Range</i>
     * @see EventCountsChart
     */
    static String Timeline_ui_countsview_menuItem_zoomIntoTimeRange() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Timeline.ui.countsview.menuItem.zoomIntoTimeRange");
    }
    /**
     * @return <i>Error zooming to interval.</i>
     * @see EventCountsChart
     */
    static String ZoomToIntervalAction_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ZoomToIntervalAction.errorMessage");
    }
    private Bundle() {}
}
