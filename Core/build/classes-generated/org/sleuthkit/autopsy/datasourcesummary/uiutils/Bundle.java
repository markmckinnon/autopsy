package org.sleuthkit.autopsy.datasourcesummary.uiutils;
/** Localizable strings for {@link org.sleuthkit.autopsy.datasourcesummary.uiutils}. */
class Bundle {
    /**
     * @return <i>There was an error loading results.</i>
     * @see AbstractLoadableComponent
     */
    static String AbstractLoadableComponent_errorMessage_defaultText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AbstractLoadableComponent_errorMessage_defaultText");
    }
    /**
     * @return <i>Loading results...</i>
     * @see AbstractLoadableComponent
     */
    static String AbstractLoadableComponent_loadingMessage_defaultText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AbstractLoadableComponent_loadingMessage_defaultText");
    }
    /**
     * @return <i>No data exists.</i>
     * @see AbstractLoadableComponent
     */
    static String AbstractLoadableComponent_noDataExists_defaultText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AbstractLoadableComponent_noDataExists_defaultText");
    }
    /**
     * @return <i>Ingest is currently running.</i>
     * @see IngestRunningLabel
     */
    static String IngestRunningLabel_defaultMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "IngestRunningLabel_defaultMessage");
    }
    /**
     * @return <i>No Data</i>
     * @see PieChartPanel
     */
    static String PieChartPanel_noDataLabel() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PieChartPanel_noDataLabel");
    }
    private Bundle() {}
}
