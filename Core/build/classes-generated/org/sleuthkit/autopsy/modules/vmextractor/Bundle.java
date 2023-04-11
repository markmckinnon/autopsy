package org.sleuthkit.autopsy.modules.vmextractor;
/** Localizable strings for {@link org.sleuthkit.autopsy.modules.vmextractor}. */
class Bundle {
    /**
     * @param output_directory_name output directory name
     * @return <i>Unable to create output directory: </i>{@code output_directory_name}<i>.</i>
     * @see VMExtractorIngestModule
     */
    static String VMExtractorIngestModule_cannotCreateOutputDir_message(Object output_directory_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VMExtractorIngestModule.cannotCreateOutputDir.message", output_directory_name);
    }
    /**
     * @return <i>No open case available.</i>
     * @see VMExtractorIngestModule
     */
    static String VMExtractorIngestModule_noOpenCase_errMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VMExtractorIngestModule.noOpenCase.errMsg");
    }
    /**
     * @param data_source_name data source name
     * @return <i>Data source </i>{@code data_source_name}<i> missing Device ID</i>
     * @see VMExtractorIngestModule
     */
    static String deviceIdQueryErrMsg(Object data_source_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "deviceIdQueryErrMsg", data_source_name);
    }
    private Bundle() {}
}
