package org.sleuthkit.autopsy.timeline.ui;
/** Localizable strings for {@link org.sleuthkit.autopsy.timeline.ui}. */
class Bundle {
    /**
     * @return <i>Drag the mouse to select a time interval to zoom into.<br>Right-click for more actions.</i>
     * @see AbstractTimelineChart
     */
    static String AbstractTimelineChart_defaultTooltip_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AbstractTimelineChart.defaultTooltip.text");
    }
    /**
     * @return <i>History</i>
     * @see HistoryToolBar
     */
    static String HistoryToolBar_historyLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HistoryToolBar.historyLabel.text");
    }
    /**
     * @return <i>Clear Selected Interval</i>
     * @see IntervalSelector
     */
    static String IntervalSelector_ClearSelectedIntervalAction_tooltTipText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IntervalSelector.ClearSelectedIntervalAction.tooltTipText");
    }
    /**
     * @return <i>Zoom</i>
     * @see IntervalSelector
     */
    static String IntervalSelector_ZoomAction_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IntervalSelector.ZoomAction.name");
    }
    /**
     * @return <i>Error zooming in to the selected interval.</i>
     * @see IntervalSelector
     */
    static String IntervalSelector_zoomToSelectedInterval_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IntervalSelector.zoomToSelectedInterval.errorMessage");
    }
    /**
     * @return <i>No Visible Events</i>
     * @see ViewFrame
     */
    static String NoEventsDialog_titledPane_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "NoEventsDialog.titledPane.text");
    }
    /**
     * @return <i>Zoom History</i>
     * @see TimeLineChart
     */
    static String TimeLineChart_zoomHistoryActionGroup_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimeLineChart.zoomHistoryActionGroup.name");
    }
    /**
     * @return <i>Display Times In:</i>
     * @see TimeZonePanel
     */
    static String TimeZonePanel_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimeZonePanel.title");
    }
    /**
     * @param start_timestamp start timestamp
     * @param end_timestamp end timestamp
     * @return <i>Double-click to zoom into range:<br></i>{@code start_timestamp}<i> to </i>{@code end_timestamp}<i>.<br><br>Right-click to close.</i>
     * @see IntervalSelector
     */
    static String Timeline_ui_TimeLineChart_tooltip_text(Object start_timestamp, Object end_timestamp) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Timeline.ui.TimeLineChart.tooltip.text", start_timestamp, end_timestamp);
    }
    /**
     * @return <i>Counts</i>
     * @see ViewFrame
     */
    static String ViewFrame_countsToggle_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.countsToggle.text");
    }
    /**
     * @return <i>Error getting spanning interval.</i>
     * @see ViewFrame
     */
    static String ViewFrame_dateTimeValidator_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.dateTimeValidator.errorMessage");
    }
    /**
     * @return <i>Details</i>
     * @see ViewFrame
     */
    static String ViewFrame_detailsToggle_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.detailsToggle.text");
    }
    /**
     * @return <i>End:</i>
     * @see ViewFrame
     */
    static String ViewFrame_endLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.endLabel.text");
    }
    /**
     * @return <i>Preparing</i>
     * @see ViewFrame
     */
    static String ViewFrame_histogramTask_preparing() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.histogramTask.preparing");
    }
    /**
     * @return <i>Querying FB</i>
     * @see ViewFrame
     */
    static String ViewFrame_histogramTask_queryDb() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.histogramTask.queryDb");
    }
    /**
     * @return <i>Resetting UI</i>
     * @see ViewFrame
     */
    static String ViewFrame_histogramTask_resetUI() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.histogramTask.resetUI");
    }
    /**
     * @return <i>Rebuilding Histogram</i>
     * @see ViewFrame
     */
    static String ViewFrame_histogramTask_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.histogramTask.title");
    }
    /**
     * @return <i>Updating UI</i>
     * @see ViewFrame
     */
    static String ViewFrame_histogramTask_updateUI2() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.histogramTask.updateUI2");
    }
    /**
     * @return <i>List</i>
     * @see ViewFrame
     */
    static String ViewFrame_listToggle_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.listToggle.text");
    }
    /**
     * @return <i>Error getting spanning interval.</i>
     * @see ViewFrame
     */
    static String ViewFrame_localDateDisabler_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.localDateDisabler.errorMessage");
    }
    /**
     * @return <i>There are no events visible with the current zoom / filter settings.</i>
     * @see ViewFrame
     */
    static String ViewFrame_noEventsDialogLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.noEventsDialogLabel.text");
    }
    /**
     * @return <i>The event data has been updated, the visualization may be out of date.</i>
     * @see ViewFrame
     */
    static String ViewFrame_notification_cacheInvalidated() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.notification.cacheInvalidated");
    }
    /**
     * @return <i>Error responding to date/time picker change.</i>
     * @see ViewFrame
     */
    static String ViewFrame_pickerListener_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.pickerListener.errorMessage");
    }
    /**
     * @return <i>Error responding to range slider.</i>
     * @see ViewFrame
     */
    static String ViewFrame_rangeSliderListener_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.rangeSliderListener.errorMessage");
    }
    /**
     * @return <i>Error gettig the spanning interval.</i>
     * @see ViewFrame
     */
    static String ViewFrame_refreshTimeUI_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.refreshTimeUI.errorMessage");
    }
    /**
     * @return <i>Refresh the view to include information that is in the DB but not displayed, such as newly updated tags.</i>
     * @see ViewFrame
     */
    static String ViewFrame_refresh_longText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.refresh.longText");
    }
    /**
     * @return <i>Refresh View</i>
     * @see ViewFrame
     */
    static String ViewFrame_refresh_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.refresh.text");
    }
    /**
     * @return <i>Start:</i>
     * @see ViewFrame
     */
    static String ViewFrame_startLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.startLabel.text");
    }
    /**
     * @return <i>Tags have been created and/or deleted.  The view may not be up to date.</i>
     * @see ViewFrame
     */
    static String ViewFrame_tagsAddedOrDeleted() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.tagsAddedOrDeleted");
    }
    /**
     * @return <i>View Mode:</i>
     * @see ViewFrame
     */
    static String ViewFrame_viewModeLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.viewModeLabel.text");
    }
    /**
     * @return <i>Error pushing time range.</i>
     * @see ViewFrame
     */
    static String ViewFrame_zoomMenuButton_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.zoomMenuButton.errorMessage");
    }
    /**
     * @return <i>Zoom in/out to</i>
     * @see ViewFrame
     */
    static String ViewFrame_zoomMenuButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewFrame.zoomMenuButton.text");
    }
    /**
     * @return <i>Analyzing zoom and filter settings</i>
     * @see AbstractTimeLineView
     */
    static String ViewRefreshTask_preparing() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewRefreshTask.preparing");
    }
    private Bundle() {}
}
