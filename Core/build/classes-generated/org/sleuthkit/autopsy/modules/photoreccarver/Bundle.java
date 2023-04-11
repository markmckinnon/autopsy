package org.sleuthkit.autopsy.modules.photoreccarver;
/** Localizable strings for {@link org.sleuthkit.autopsy.modules.photoreccarver}. */
class Bundle {
    /**
     * @param extensions extensions
     * @return <i>The following extensions are invalid: </i>{@code extensions}
     * @see PhotoRecCarverFileIngestModule
     */
    static String PhotoRecCarverFileIngestModule_startUp_invalidExtensions_description(Object extensions) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PhotoRecCarverFileIngestModule_startUp_invalidExtensions_description", extensions);
    }
    /**
     * @return <i>No extensions provided for PhotoRec to carve.</i>
     * @see PhotoRecCarverFileIngestModule
     */
    static String PhotoRecCarverFileIngestModule_startUp_noExtensionsProvided_description() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PhotoRecCarverFileIngestModule_startUp_noExtensionsProvided_description");
    }
    /**
     * @return <i>Insufficient permissions accessing</i>
     * @see PhotoRecCarverFileIngestModule
     */
    static String PhotoRecIngestModule_PermissionsNotSufficient() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PhotoRecIngestModule.PermissionsNotSufficient");
    }
    /**
     * @return <i>See 'Shared Drive Authentication' in Autopsy help.</i>
     * @see PhotoRecCarverFileIngestModule
     */
    static String PhotoRecIngestModule_PermissionsNotSufficientSeeReference() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PhotoRecIngestModule.PermissionsNotSufficientSeeReference");
    }
    /**
     * @return <i>PhotoRec cannot operate with a UNC path containing IP addresses.</i>
     * @see PhotoRecCarverFileIngestModule
     */
    static String PhotoRecIngestModule_nonHostnameUNCPathUsed() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PhotoRecIngestModule.nonHostnameUNCPathUsed");
    }
    /**
     * @param output_directory_name output directory name
     * @return <i>Unable to create output directory: </i>{@code output_directory_name}<i>.</i>
     * @see PhotoRecCarverFileIngestModule
     */
    static String cannotCreateOutputDir_message(Object output_directory_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "cannotCreateOutputDir.message", output_directory_name);
    }
    /**
     * @return <i>Unable to execute PhotoRec.</i>
     * @see PhotoRecCarverFileIngestModule
     */
    static String cannotRunExecutable_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "cannotRunExecutable.message");
    }
    /**
     * @return <i>Unable to locate PhotoRec executable.</i>
     * @see PhotoRecCarverFileIngestModule
     */
    static String missingExecutable_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "missingExecutable.message");
    }
    /**
     * @return <i>The selected file ingest filter ignores unallocated space. This module carves unallocated space. Please choose a filter which does not ignore unallocated space or disable this module.</i>
     * @see PhotoRecCarverFileIngestModule
     */
    static String unallocatedSpaceProcessingSettingsError_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "unallocatedSpaceProcessingSettingsError.message");
    }
    /**
     * @return <i>PhotoRec module is supported on Windows platforms only.</i>
     * @see PhotoRecCarverFileIngestModule
     */
    static String unsupportedOS_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "unsupportedOS.message");
    }
    private Bundle() {}
}
