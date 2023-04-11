package org.sleuthkit.autopsy.healthmonitor;
/** Localizable strings for {@link org.sleuthkit.autopsy.healthmonitor}. */
class Bundle {
    /**
     * @return <i>One day</i>
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_DateRange_oneDay() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.DateRange.oneDay");
    }
    /**
     * @return <i>One month</i>
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_DateRange_oneMonth() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.DateRange.oneMonth");
    }
    /**
     * @return <i>One week</i>
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_DateRange_oneWeek() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.DateRange.oneWeek");
    }
    /**
     * @return <i>Two weeks</i>
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_DateRange_twoWeeks() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.DateRange.twoWeeks");
    }
    /**
     * @return <i>Disable monitor</i>
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_createAdminPanel_disableButton() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.createAdminPanel.disableButton");
    }
    /**
     * @return <i>Enable monitor</i>
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_createAdminPanel_enableButton() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.createAdminPanel.enableButton");
    }
    /**
     * @return <i>Filter by host</i>
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_createTimingControlPanel_filterByHost() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.createTimingControlPanel.filterByHost");
    }
    /**
     * @return <i>Max days to display</i>
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_createTimingControlPanel_maxDays() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.createTimingControlPanel.maxDays");
    }
    /**
     * @return <i>Show trend line</i>
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_createTimingControlPanel_showTrendLine() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.createTimingControlPanel.showTrendLine");
    }
    /**
     * @return <i>Do not plot outliers</i>
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_createTimingControlPanel_skipOutliers() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.createTimingControlPanel.skipOutliers");
    }
    /**
     * @return <i>No data to display - monitor is not enabled</i>
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_createTimingPanel_noData() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.createTimingPanel.noData");
    }
    /**
     * @return <i>Timing Metrics</i>
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_createTimingPanel_timingMetricsTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.createTimingPanel.timingMetricsTitle");
    }
    /**
     * @return <i>Max days to display</i>
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_createUserControlPanel_maxDays() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.createUserControlPanel.maxDays");
    }
    /**
     * @param Report_file_name Report file name
     * @return <i>Report saved to: </i>{@code Report_file_name}
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_createUserControlPanel_reportDone(Object Report_file_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.createUserControlPanel.reportDone", Report_file_name);
    }
    /**
     * @return <i>Error generating report</i>
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_createUserControlPanel_reportError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.createUserControlPanel.reportError");
    }
    /**
     * @return <i>Generate Report</i>
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_createUserControlPanel_userReportButton() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.createUserControlPanel.userReportButton");
    }
    /**
     * @return <i>No data to display - monitor is not enabled</i>
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_createUserPanel_noData() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.createUserPanel.noData");
    }
    /**
     * @return <i>User Metrics</i>
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_createUserPanel_userMetricsTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.createUserPanel.userMetricsTitle");
    }
    /**
     * @return <i>Health Monitor</i>
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_display_dashboardTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.display.dashboardTitle");
    }
    /**
     * @return <i>Error creating health monitor dashboard</i>
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_display_errorCreatingDashboard() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.display.errorCreatingDashboard");
    }
    /**
     * @return <i>No data to display</i>
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_updateTimingMetricGraphs_noData() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.updateTimingMetricGraphs.noData");
    }
    /**
     * @return <i>No data to display</i>
     * @see HealthMonitorDashboard
     */
    static String HealthMonitorDashboard_updateUserMetricGraphs_noData() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HealthMonitorDashboard.updateUserMetricGraphs.noData");
    }
    /**
     * @return <i>displaying time in </i>
     * @see TimingMetricGraphPanel
     */
    static String TimingMetricGraphPanel_paintComponent_displayingTime() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimingMetricGraphPanel.paintComponent.displayingTime");
    }
    /**
     * @return <i>hours</i>
     * @see TimingMetricGraphPanel
     */
    static String TimingMetricGraphPanel_paintComponent_hours() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimingMetricGraphPanel.paintComponent.hours");
    }
    /**
     * @return <i>microseconds</i>
     * @see TimingMetricGraphPanel
     */
    static String TimingMetricGraphPanel_paintComponent_microseconds() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimingMetricGraphPanel.paintComponent.microseconds");
    }
    /**
     * @return <i>milliseconds</i>
     * @see TimingMetricGraphPanel
     */
    static String TimingMetricGraphPanel_paintComponent_milliseconds() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimingMetricGraphPanel.paintComponent.milliseconds");
    }
    /**
     * @return <i>minutes</i>
     * @see TimingMetricGraphPanel
     */
    static String TimingMetricGraphPanel_paintComponent_minutes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimingMetricGraphPanel.paintComponent.minutes");
    }
    /**
     * @return <i>nanoseconds</i>
     * @see TimingMetricGraphPanel
     */
    static String TimingMetricGraphPanel_paintComponent_nanoseconds() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimingMetricGraphPanel.paintComponent.nanoseconds");
    }
    /**
     * @return <i>seconds</i>
     * @see TimingMetricGraphPanel
     */
    static String TimingMetricGraphPanel_paintComponent_seconds() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimingMetricGraphPanel.paintComponent.seconds");
    }
    /**
     * @return <i>Cases open</i>
     * @see UserMetricGraphPanel
     */
    static String UserMetricGraphPanel_constructor_casesOpen() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UserMetricGraphPanel.constructor.casesOpen");
    }
    /**
     * @return <i>Users logged in - examiner nodes in blue, auto ingest nodes in green</i>
     * @see UserMetricGraphPanel
     */
    static String UserMetricGraphPanel_constructor_loggedIn() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UserMetricGraphPanel.constructor.loggedIn");
    }
    private Bundle() {}
}
