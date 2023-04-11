package org.sleuthkit.autopsy.report.modules.excel;
/** Localizable strings for {@link org.sleuthkit.autopsy.report.modules.excel}. */
class Bundle {
    /**
     * @return <i>Value is too long to fit into an Excel cell. </i>
     * @see ExcelReport
     */
    static String ReportExcel_exceptionMessage_dataTooLarge() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportExcel.exceptionMessage.dataTooLarge");
    }
    /**
     * @return <i>Error showing data into an Excel cell.</i>
     * @see ExcelReport
     */
    static String ReportExcel_exceptionMessage_errorText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportExcel.exceptionMessage.errorText");
    }
    /**
     * @return <i>Case Name:</i>
     * @see ExcelReport
     */
    static String ReportExcel_writeSummary_caseName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportExcel.writeSummary.caseName");
    }
    /**
     * @return <i>Case Notes:</i>
     * @see ExcelReport
     */
    static String ReportExcel_writeSummary_caseNotes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportExcel.writeSummary.caseNotes");
    }
    /**
     * @return <i>Case Number:</i>
     * @see ExcelReport
     */
    static String ReportExcel_writeSummary_caseNum() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportExcel.writeSummary.caseNum");
    }
    /**
     * @return <i>Examiner:</i>
     * @see ExcelReport
     */
    static String ReportExcel_writeSummary_examiner() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportExcel.writeSummary.examiner");
    }
    /**
     * @return <i>Number of data sources in case:</i>
     * @see ExcelReport
     */
    static String ReportExcel_writeSummary_numImages() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportExcel.writeSummary.numImages");
    }
    /**
     * @return <i>Summary</i>
     * @see ExcelReport
     */
    static String ReportExcel_writeSummary_sheetName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportExcel.writeSummary.sheetName");
    }
    /**
     * @return <i>Summary</i>
     * @see ExcelReport
     */
    static String ReportExcel_writeSummary_summary() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportExcel.writeSummary.summary");
    }
    private Bundle() {}
}
