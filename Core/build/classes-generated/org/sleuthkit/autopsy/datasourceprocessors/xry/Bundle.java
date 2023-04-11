package org.sleuthkit.autopsy.datasourceprocessors.xry;
/** Localizable strings for {@link org.sleuthkit.autopsy.datasourceprocessors.xry}. */
class Bundle {
    /**
     * @return <i>Top level path [ %s ] is not readable</i>
     * @see XRYDataSourceProcessor
     */
    static String XRYDataSourceProcessor_childNotReadable() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "XRYDataSourceProcessor.childNotReadable");
    }
    /**
     * @return <i>XRY Text Export</i>
     * @see XRYDataSourceProcessor
     */
    static String XRYDataSourceProcessor_dataSourceType() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "XRYDataSourceProcessor.dataSourceType");
    }
    /**
     * @return <i>Added %s to the case database</i>
     * @see XRYDataSourceProcessor
     */
    static String XRYDataSourceProcessor_fileAdded() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "XRYDataSourceProcessor.fileAdded");
    }
    /**
     * @return <i>I/O error occured trying to test the selected folder</i>
     * @see XRYDataSourceProcessor
     */
    static String XRYDataSourceProcessor_ioError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "XRYDataSourceProcessor.ioError");
    }
    /**
     * @return <i>No case is open.</i>
     * @see XRYDataSourceProcessor
     */
    static String XRYDataSourceProcessor_noCurrentCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "XRYDataSourceProcessor.noCurrentCase");
    }
    /**
     * @return <i>Please select a folder containing exported XRY text files</i>
     * @see XRYDataSourceProcessor
     */
    static String XRYDataSourceProcessor_noPathSelected() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "XRYDataSourceProcessor.noPathSelected");
    }
    /**
     * @return <i>The selected path is not a folder</i>
     * @see XRYDataSourceProcessor
     */
    static String XRYDataSourceProcessor_notAFolder() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "XRYDataSourceProcessor.notAFolder");
    }
    /**
     * @return <i>Selected path is not readable</i>
     * @see XRYDataSourceProcessor
     */
    static String XRYDataSourceProcessor_notReadable() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "XRYDataSourceProcessor.notReadable");
    }
    /**
     * @return <i>Selected folder did not contain any XRY text files</i>
     * @see XRYDataSourceProcessor
     */
    static String XRYDataSourceProcessor_notXRYFolder() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "XRYDataSourceProcessor.notXRYFolder");
    }
    /**
     * @return <i>Preparing to add files to the case database</i>
     * @see XRYDataSourceProcessor
     */
    static String XRYDataSourceProcessor_preppingFiles() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "XRYDataSourceProcessor.preppingFiles");
    }
    /**
     * @return <i>Processing all XRY files...</i>
     * @see XRYDataSourceProcessor
     */
    static String XRYDataSourceProcessor_processingFiles() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "XRYDataSourceProcessor.processingFiles");
    }
    /**
     * @return <i>Internal error occurred while processing XRY report</i>
     * @see XRYDataSourceProcessor
     */
    static String XRYDataSourceProcessor_unexpectedError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "XRYDataSourceProcessor.unexpectedError");
    }
    private Bundle() {}
}
