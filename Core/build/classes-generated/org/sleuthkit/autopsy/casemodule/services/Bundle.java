package org.sleuthkit.autopsy.casemodule.services;
/** Localizable strings for {@link org.sleuthkit.autopsy.casemodule.services}. */
class Bundle {
    /**
     * @return <i>Bookmark</i>
     * @see TagNameDefinition
     */
    static String TagNameDefinition_predefTagNames_bookmark_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TagNameDefinition.predefTagNames.bookmark.text");
    }
    /**
     * @return <i>Follow Up</i>
     * @see TagNameDefinition
     */
    static String TagNameDefinition_predefTagNames_followUp_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TagNameDefinition.predefTagNames.followUp.text");
    }
    /**
     * @return <i>Notable Item</i>
     * @see TagNameDefinition
     */
    static String TagNameDefinition_predefTagNames_notableItem_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TagNameDefinition.predefTagNames.notableItem.text");
    }
    /**
     * @return <i>Tag descriptions may not contain commas (,) or semicolons (;)</i>
     * @see TagNameDialog
     */
    static String TagNameDialog_JOptionPane_tagDescriptionIllegalCharacters_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TagNameDialog.JOptionPane.tagDescriptionIllegalCharacters.message");
    }
    /**
     * @return <i>Invalid character in tag description</i>
     * @see TagNameDialog
     */
    static String TagNameDialog_JOptionPane_tagDescriptionIllegalCharacters_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TagNameDialog.JOptionPane.tagDescriptionIllegalCharacters.title");
    }
    /**
     * @return <i>Description:</i>
     * @see TagNameDialog
     */
    static String TagNameDialog_descriptionLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TagNameDialog.descriptionLabel.text");
    }
    /**
     * @return <i>Edit Tag</i>
     * @see TagNameDialog
     */
    static String TagNameDialog_editTitle_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TagNameDialog.editTitle.text");
    }
    /**
     * @return <i>Tag indicates item is notable.</i>
     * @see TagNameDialog
     */
    static String TagNameDialog_notableCheckbox_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TagNameDialog.notableCheckbox.text");
    }
    /**
     * @return <i>Tag name must be unique. A tag with this name already exists.</i>
     * @see TagOptionsPanel
     */
    static String TagOptionsPanel_TagNameDialog_tagNameAlreadyExists_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TagOptionsPanel.TagNameDialog.tagNameAlreadyExists.message");
    }
    /**
     * @return <i>Duplicate Tag Name</i>
     * @see TagOptionsPanel
     */
    static String TagOptionsPanel_TagNameDialog_tagNameAlreadyExists_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TagOptionsPanel.TagNameDialog.tagNameAlreadyExists.title");
    }
    /**
     * @return <i>Tag Description:</i>
     * @see TagOptionsPanel
     */
    static String TagOptionsPanel_descriptionLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TagOptionsPanel.descriptionLabel.text");
    }
    /**
     * @return <i>Edit Tag</i>
     * @see TagOptionsPanel
     */
    static String TagOptionsPanel_editTagNameButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TagOptionsPanel.editTagNameButton.text");
    }
    /**
     * @return <i>Cannot make changes to existing tags when ingest is running!</i>
     * @see TagOptionsPanel
     */
    static String TagOptionsPanel_ingestRunningWarningLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TagOptionsPanel.ingestRunningWarningLabel.text");
    }
    /**
     * @return <i>Tag indicates item is notable: </i>
     * @see TagOptionsPanel
     */
    static String TagOptionsPanel_isNotableLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TagOptionsPanel.isNotableLabel.text");
    }
    /**
     * @return 
     * @see TagOptionsPanel
     */
    static String TagOptionsPanel_notableYesOrNoLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TagOptionsPanel.notableYesOrNoLabel.text");
    }
    /**
     * @return <i>Create and manage tags. Tags can be applied to files and results in the case. Notable tags will cause items tagged with them to be flagged as notable when using a central repository. Changing the status of a tag will only effect items in the current case.</i>
     * @see TagOptionsPanel
     */
    static String TagOptionsPanel_panelDescriptionTextArea_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TagOptionsPanel.panelDescriptionTextArea.text");
    }
    /**
     * @return <i> (Notable)</i>
     * @see TagsManager
     */
    static String TagsManager_notableTagEnding_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TagsManager.notableTagEnding.text");
    }
    private Bundle() {}
}
