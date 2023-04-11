package org.sleuthkit.autopsy.report;
/** Localizable strings for {@link org.sleuthkit.autopsy.report}. */
class Bundle {
    /**
     * @return <i>Canceled</i>
     * @see ReportProgressPanel
     */
    static String ReportProgressPanel_progress_canceled() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportProgressPanel.progress.canceled");
    }
    /**
     * @return <i>Complete</i>
     * @see ReportProgressPanel
     */
    static String ReportProgressPanel_progress_complete() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportProgressPanel.progress.complete");
    }
    /**
     * @return <i>Error</i>
     * @see ReportProgressPanel
     */
    static String ReportProgressPanel_progress_error() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportProgressPanel.progress.error");
    }
    /**
     * @return <i>Queuing...</i>
     * @see ReportProgressPanel
     */
    static String ReportProgressPanel_progress_queuing() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportProgressPanel.progress.queuing");
    }
    /**
     * @return <i>Running...</i>
     * @see ReportProgressPanel
     */
    static String ReportProgressPanel_progress_running() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportProgressPanel.progress.running");
    }
    private Bundle() {}
}
