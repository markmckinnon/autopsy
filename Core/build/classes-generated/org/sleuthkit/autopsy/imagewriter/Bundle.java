package org.sleuthkit.autopsy.imagewriter;
/** Localizable strings for {@link org.sleuthkit.autopsy.imagewriter}. */
class Bundle {
    /**
     * @param data_source_name data source name
     * @return <i>Finishing acquisition of </i>{@code data_source_name}<i> (unplug device to cancel)</i>
     * @see ImageWriter
     */
    static String ImageWriter_progressBar_message(Object data_source_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ImageWriter.progressBar.message", data_source_name);
    }
    private Bundle() {}
}
