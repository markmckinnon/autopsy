package org.sleuthkit.autopsy.test;
/** Localizable strings for {@link org.sleuthkit.autopsy.test}. */
class Bundle {
    /**
     * @return <i>Error creating custom artifact type.</i>
     * @see CustomArtifactsCreatorDataSourceIngestModule
     */
    static String CustomArtifactsCreatorDataSourceIngestModule_exceptionMessage_errorCreatingCustomType() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CustomArtifactsCreatorDataSourceIngestModule.exceptionMessage.errorCreatingCustomType");
    }
    /**
     * @return <i>Error creating custom artifact type.</i>
     * @see CustomArtifactsCreatorFileIngestModule
     */
    static String CustomArtifactsCreatorFileIngestModule_exceptionMessage_errorCreatingCustomType() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CustomArtifactsCreatorFileIngestModule.exceptionMessage.errorCreatingCustomType");
    }
    /**
     * @return <i>Error creating custom artifact type.</i>
     * @see InterestingArtifactCreatorIngestModule
     */
    static String InterestingArtifactCreatorIngestModule_exceptionMessage_errorCreatingCustomType() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "InterestingArtifactCreatorIngestModule.exceptionMessage.errorCreatingCustomType");
    }
    private Bundle() {}
}
