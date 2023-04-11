package org.sleuthkit.autopsy.modules.filetypeid;
/** Localizable strings for {@link org.sleuthkit.autopsy.modules.filetypeid}. */
class Bundle {
    /**
     * @param type_name type name
     * @return <i>Invalid character in MIME type, </i>{@code type_name}<i> has been suggested instead</i>
     * @see AddFileTypePanel
     */
    static String AddFileTypePanel_containsIllegalCharacter_message(Object type_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddFileTypePanel.containsIllegalCharacter.message", type_name);
    }
    /**
     * @return <i>Invalid Character in MIME Type</i>
     * @see AddFileTypePanel
     */
    static String AddFileTypePanel_containsIllegalCharacter_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddFileTypePanel.containsIllegalCharacter.title");
    }
    /**
     * @return <i>Form of MIME type should be: media type/media subtype</i>
     * @see AddFileTypePanel
     */
    static String AddFileTypePanel_mimeFormatLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddFileTypePanel.mimeFormatLabel.text");
    }
    /**
     * @param media_subtype media subtype
     * @return <i>MIME type must be of form: media type/media subtype. Custom/</i>{@code media_subtype}<i> has been suggested instead.</i>
     * @see AddFileTypePanel
     */
    static String AddFileTypePanel_nonStandardMIMEType_message(Object media_subtype) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddFileTypePanel.nonStandardMIMEType.message", media_subtype);
    }
    /**
     * @return <i>Non-standard MIME Type</i>
     * @see AddFileTypePanel
     */
    static String AddFileTypePanel_nonStandardMIMEType_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddFileTypePanel.nonStandardMIMEType.title");
    }
    /**
     * @return <i>OK</i>
     * @see AddFileTypeSignatureDialog
     */
    static String AddFileTypeSignatureDialog_addButton_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddFileTypeSignatureDialog.addButton.title");
    }
    /**
     * @return <i>Cancel</i>
     * @see AddFileTypeSignatureDialog
     */
    static String AddFileTypeSignatureDialog_cancelButton_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddFileTypeSignatureDialog.cancelButton.title");
    }
    /**
     * @return <i>Invalid signature</i>
     * @see AddFileTypeSignatureDialog
     */
    static String AddFileTypeSignatureDialog_invalidSignature_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddFileTypeSignatureDialog.invalidSignature.message");
    }
    /**
     * @return <i>Couldn't get signatures string</i>
     * @see AddFileTypeSignaturePanel
     */
    static String AddFileTypeSignaturePanel_signatureStringFail_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddFileTypeSignaturePanel.signatureStringFail.text");
    }
    /**
     * @return <i>OK</i>
     * @see AddFileTypeDialog
     */
    static String AddMimeTypeDialog_addButton_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddMimeTypeDialog.addButton.title");
    }
    /**
     * @return <i>Cancel</i>
     * @see AddFileTypeDialog
     */
    static String AddMimeTypeDialog_cancelButton_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddMimeTypeDialog.cancelButton.title");
    }
    /**
     * @return <i>Interesting files set name is required if alert is requested.</i>
     * @see AddFileTypePanel
     */
    static String AddMimeTypePanel_emptySetName_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddMimeTypePanel.emptySetName.message");
    }
    /**
     * @return <i>Missing Interesting Files Set Name</i>
     * @see AddFileTypePanel
     */
    static String AddMimeTypePanel_emptySetName_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddMimeTypePanel.emptySetName.title");
    }
    /**
     * @return <i>Must have at least one signature.</i>
     * @see AddFileTypePanel
     */
    static String AddMimeTypePanel_emptySigList_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddMimeTypePanel.emptySigList.message");
    }
    /**
     * @return <i>Invalid Signature List</i>
     * @see AddFileTypePanel
     */
    static String AddMimeTypePanel_emptySigList_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddMimeTypePanel.emptySigList.title");
    }
    /**
     * @return <i>File Type</i>
     * @see AddFileTypeDialog
     */
    static String AddMimeTypedialog_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddMimeTypedialog.title");
    }
    /**
     * @return <i>Unable to run file type detection.</i>
     * @see FileTypeIdIngestModule
     */
    static String CannotRunFileTypeDetection() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CannotRunFileTypeDetection");
    }
    /**
     * @return <i>Global File Type Identification Settings</i>
     * @see FileTypeIdGlobalSettingsPanel
     */
    static String FileTypeIdGlobalSettingsPanel_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileTypeIdGlobalSettingsPanel.Title");
    }
    private Bundle() {}
}
