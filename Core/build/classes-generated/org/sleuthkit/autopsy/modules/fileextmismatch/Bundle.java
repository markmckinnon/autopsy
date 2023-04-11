package org.sleuthkit.autopsy.modules.fileextmismatch;
/** Localizable strings for {@link org.sleuthkit.autopsy.modules.fileextmismatch}. */
class Bundle {
    /**
     * @return <i>Could not write file extension settings.</i>
     * @see AddFileExtensionAction
     */
    static String AddFileExtensionAction_writeError_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddFileExtensionAction.writeError.message");
    }
    /**
     * @return <i>Unable to run file type detection.</i>
     * @see FileExtMismatchIngestModule
     */
    static String CannotRunFileTypeDetection() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CannotRunFileTypeDetection");
    }
    /**
     * @return <i>Failed to index file extension mismatch artifact for keyword search.</i>
     * @see FileExtMismatchIngestModule
     */
    static String FileExtMismatchIngestModule_indexError_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileExtMismatchIngestModule.indexError.message");
    }
    /**
     * @return <i>Could not read settings.</i>
     * @see FileExtMismatchIngestModule
     */
    static String FileExtMismatchIngestModule_readError_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileExtMismatchIngestModule.readError.message");
    }
    /**
     * @return <i>Global File Extension Mismatch Identification Settings</i>
     * @see FileExtMismatchSettingsPanel
     */
    static String FileExtMismatchSettingsPanel_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileExtMismatchSettingsPanel.Title");
    }
    private Bundle() {}
}
