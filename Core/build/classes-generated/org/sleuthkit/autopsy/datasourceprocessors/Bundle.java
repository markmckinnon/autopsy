package org.sleuthkit.autopsy.datasourceprocessors;
/** Localizable strings for {@link org.sleuthkit.autopsy.datasourceprocessors}. */
class Bundle {
    /**
     * @return <i>for device </i>
     * @see AddRawImageTask
     */
    static String AddRawImageTask_for_device() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddRawImageTask.for.device");
    }
    /**
     * @return <i>Critical error adding </i>
     * @see AddRawImageTask
     */
    static String AddRawImageTask_image_critical_error_adding() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddRawImageTask.image.critical.error.adding");
    }
    /**
     * @return <i>Non-critical error adding </i>
     * @see AddRawImageTask
     */
    static String AddRawImageTask_image_noncritical_error_adding() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddRawImageTask.image.noncritical.error.adding");
    }
    /**
     * @return <i>is not existing.</i>
     * @see AddRawImageTask
     */
    static String AddRawImageTask_image_notExisting() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddRawImageTask.image.notExisting");
    }
    /**
     * @return <i>No open case available.</i>
     * @see AddRawImageTask
     */
    static String AddRawImageTask_noOpenCase_errMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddRawImageTask.noOpenCase.errMsg");
    }
    /**
     * @return <i>Adding raw image: </i>
     * @see AddRawImageTask
     */
    static String AddRawImageTask_progress_add_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddRawImageTask.progress.add.text");
    }
    /**
     * @return <i>Path to multi-user data source is on "C:" drive</i>
     * @see RawDSInputPanel
     */
    static String RawDSInputPanel_error_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RawDSInputPanel.error.text");
    }
    /**
     * @return <i>Exception while getting open case.</i>
     * @see RawDSInputPanel
     */
    static String RawDSInputPanel_noOpenCase_errMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RawDSInputPanel.noOpenCase.errMsg");
    }
    /**
     * @return <i>Unallocated Space Image File</i>
     * @see RawDSProcessor
     */
    static String RawDSProcessor_dataSourceType() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RawDSProcessor.dataSourceType");
    }
    private Bundle() {}
}
