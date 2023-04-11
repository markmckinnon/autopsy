package org.sleuthkit.autopsy.modules.encryptiondetection;
/** Localizable strings for {@link org.sleuthkit.autopsy.modules.encryptiondetection}. */
class Bundle {
    /**
     * @return <i>Bitlocker encryption detected.</i>
     * @see EncryptionDetectionDataSourceIngestModule
     */
    static String EncryptionDetectionDataSourceIngestModule_artifactComment_bitlocker() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EncryptionDetectionDataSourceIngestModule.artifactComment.bitlocker");
    }
    /**
     * @return <i>Suspected encryption due to high entropy (%f).</i>
     * @see EncryptionDetectionDataSourceIngestModule
     */
    static String EncryptionDetectionDataSourceIngestModule_artifactComment_suspected() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EncryptionDetectionDataSourceIngestModule.artifactComment.suspected");
    }
    /**
     * @return <i>Checking image for encryption.</i>
     * @see EncryptionDetectionDataSourceIngestModule
     */
    static String EncryptionDetectionDataSourceIngestModule_processing_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EncryptionDetectionDataSourceIngestModule.processing.message");
    }
    /**
     * @return <i>Password protection detected.</i>
     * @see EncryptionDetectionModuleFactory
     */
    static String EncryptionDetectionFileIngestModule_artifactComment_password() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EncryptionDetectionFileIngestModule.artifactComment.password");
    }
    /**
     * @return <i>Suspected encryption due to high entropy (%f).</i>
     * @see EncryptionDetectionFileIngestModule
     */
    static String EncryptionDetectionFileIngestModule_artifactComment_suspected() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EncryptionDetectionFileIngestModule.artifactComment.suspected");
    }
    /**
     * @return <i>Looks for files with the specified minimum entropy.</i>
     * @see EncryptionDetectionModuleFactory
     */
    static String EncryptionDetectionFileIngestModule_getDesc_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EncryptionDetectionFileIngestModule.getDesc.text");
    }
    /**
     * @return <i>Encryption Detection</i>
     * @see EncryptionDetectionModuleFactory
     */
    static String EncryptionDetectionFileIngestModule_moduleName_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EncryptionDetectionFileIngestModule.moduleName.text");
    }
    /**
     * @return <i>Minimum entropy input must be a number between 6.0 and 8.0.</i>
     * @see EncryptionDetectionTools
     */
    static String EncryptionDetectionTools_errorMessage_minimumEntropyInput() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EncryptionDetectionTools.errorMessage.minimumEntropyInput");
    }
    /**
     * @return <i>Minimum file size input must be an integer (in megabytes) of 1 or greater.</i>
     * @see EncryptionDetectionTools
     */
    static String EncryptionDetectionTools_errorMessage_minimumFileSizeInput() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EncryptionDetectionTools.errorMessage.minimumFileSizeInput");
    }
    private Bundle() {}
}
