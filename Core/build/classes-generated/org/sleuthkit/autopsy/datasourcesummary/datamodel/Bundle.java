package org.sleuthkit.autopsy.datasourcesummary.datamodel;
/** Localizable strings for {@link org.sleuthkit.autopsy.datasourcesummary.datamodel}. */
class Bundle {
    /**
     * @return <i>Call Log</i>
     * @see UserActivitySummary
     */
    static String DataSourceUserActivitySummary_getRecentAccounts_calllogMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceUserActivitySummary_getRecentAccounts_calllogMessage");
    }
    /**
     * @return <i>Email Message</i>
     * @see UserActivitySummary
     */
    static String DataSourceUserActivitySummary_getRecentAccounts_emailMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceUserActivitySummary_getRecentAccounts_emailMessage");
    }
    private Bundle() {}
}
