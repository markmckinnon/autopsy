package org.sleuthkit.autopsy.modules.yara;
/** Localizable strings for {@link org.sleuthkit.autopsy.modules.yara}. */
class Bundle {
    /**
     * @return <i>Unable to run YARA ingest, list of YARA rule sets was empty.</i>
     * @see YaraIngestHelper
     */
    static String YaraIngestModule_no_ruleSets() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "YaraIngestModule_no_ruleSets");
    }
    /**
     * @return <i>The YARA ingest module is only available on 64bit Windows.</i>
     * @see YaraIngestModule
     */
    static String YaraIngestModule_windows_error_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "YaraIngestModule_windows_error_msg");
    }
    /**
     * @return <i>Unable to compile YARA rules files. Unable to find executable at.</i>
     * @see YaraIngestHelper
     */
    static String YaraIngestModule_yarac_not_found() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "YaraIngestModule_yarac_not_found");
    }
    /**
     * @return <i>The YARA Analyzer uses YARA to search files for textual or binary patterns.</i>
     * @see YaraIngestModuleFactory
     */
    static String Yara_Module_Description() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Yara_Module_Description");
    }
    /**
     * @return <i>YARA Analyzer</i>
     * @see YaraIngestModuleFactory
     */
    static String Yara_Module_Name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Yara_Module_Name");
    }
    private Bundle() {}
}
