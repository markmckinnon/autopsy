package org.sleuthkit.autopsy.report.modules.caseuco;
/** Localizable strings for {@link org.sleuthkit.autopsy.report.modules.caseuco}. */
class Bundle {
    /**
     * @return <i>Warning, this report will be created before ingest services completed</i>
     * @see CaseUcoReportModule
     */
    static String CaseUcoReportModule_ingestWarning() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseUcoReportModule.ingestWarning");
    }
    /**
     * @return <i>I/O error encountered while generating report</i>
     * @see CaseUcoReportModule
     */
    static String CaseUcoReportModule_ioError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseUcoReportModule.ioError");
    }
    /**
     * @return <i>No case is currently open</i>
     * @see CaseUcoReportModule
     */
    static String CaseUcoReportModule_noCaseOpen() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseUcoReportModule.noCaseOpen");
    }
    /**
     * @return <i>No data source selected for CASE-UCO report</i>
     * @see CaseUcoReportModule
     */
    static String CaseUcoReportModule_noDataSourceSelected() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseUcoReportModule.noDataSourceSelected");
    }
    /**
     * @return <i>CASE-UCO settings panel has not been initialized</i>
     * @see CaseUcoReportModule
     */
    static String CaseUcoReportModule_notInitialized() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseUcoReportModule.notInitialized");
    }
    /**
     * @return <i>Processing datasource: %s</i>
     * @see CaseUcoReportModule
     */
    static String CaseUcoReportModule_processingDataSource() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseUcoReportModule.processingDataSource");
    }
    /**
     * @return <i>CASE-UCO Report</i>
     * @see CaseUcoReportModule
     */
    static String CaseUcoReportModule_srcModuleName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseUcoReportModule.srcModuleName");
    }
    /**
     * @return <i>TskCoreException [%s] encountered while generating the report. Please reference the log for more details.</i>
     * @see CaseUcoReportModule
     */
    static String CaseUcoReportModule_tskCoreException() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseUcoReportModule.tskCoreException");
    }
    /**
     * @return <i>Unable to create directory for CASE-UCO report</i>
     * @see CaseUcoReportModule
     */
    static String CaseUcoReportModule_unableToCreateDirectories() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CaseUcoReportModule.unableToCreateDirectories");
    }
    private Bundle() {}
}
