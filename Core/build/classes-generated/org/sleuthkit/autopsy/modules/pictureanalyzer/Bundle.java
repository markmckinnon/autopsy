package org.sleuthkit.autopsy.modules.pictureanalyzer;
/** Localizable strings for {@link org.sleuthkit.autopsy.modules.pictureanalyzer}. */
class Bundle {
    /**
     * @return <i>Performs general analysis on picture files, including extracting EXIF metadata and converting between formats.</i>
     * @see PictureAnalyzerIngestModuleFactory
     */
    static String PictureAnalyzerIngestModuleFactory_module_description() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PictureAnalyzerIngestModuleFactory.module_description");
    }
    /**
     * @return <i>Picture Analyzer</i>
     * @see PictureAnalyzerIngestModuleFactory
     */
    static String PictureAnalyzerIngestModuleFactory_module_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PictureAnalyzerIngestModuleFactory.module_name");
    }
    /**
     * @return <i>Cannot run file type detection.</i>
     * @see PictureAnalyzerIngestModule
     */
    static String PictureAnalyzerIngestModule_cannot_run_file_type() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PictureAnalyzerIngestModule.cannot_run_file_type");
    }
    private Bundle() {}
}
