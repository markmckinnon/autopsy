package org.sleuthkit.autopsy.actions;
/** Localizable strings for {@link org.sleuthkit.autopsy.actions}. */
class Bundle {
    /**
     * @return <i>Add Result Tags</i>
     * @see AddBlackboardArtifactTagAction
     */
    static String AddBlackboardArtifactTagAction_pluralTagResult() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddBlackboardArtifactTagAction.pluralTagResult");
    }
    /**
     * @return <i>Add Result Tag</i>
     * @see AddBlackboardArtifactTagAction
     */
    static String AddBlackboardArtifactTagAction_singularTagResult() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddBlackboardArtifactTagAction.singularTagResult");
    }
    /**
     * @return <i>Tagging Error</i>
     * @see AddBlackboardArtifactTagAction
     */
    static String AddBlackboardArtifactTagAction_taggingErr() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddBlackboardArtifactTagAction.taggingErr");
    }
    /**
     * @param artifactName artifactName
     * @return <i>Unable to tag </i>{@code artifactName}<i>.</i>
     * @see AddBlackboardArtifactTagAction
     */
    static String AddBlackboardArtifactTagAction_unableToTag_msg(Object artifactName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddBlackboardArtifactTagAction.unableToTag.msg", artifactName);
    }
    /**
     * @return <i>Cannot Apply Tag</i>
     * @see AddContentTagAction
     */
    static String AddContentTagAction_cannotApplyTagErr() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddContentTagAction.cannotApplyTagErr");
    }
    /**
     * @return <i>Add File Tags</i>
     * @see AddContentTagAction
     */
    static String AddContentTagAction_pluralTagFile() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddContentTagAction.pluralTagFile");
    }
    /**
     * @return <i>Add File Tag</i>
     * @see AddContentTagAction
     */
    static String AddContentTagAction_singularTagFile() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddContentTagAction.singularTagFile");
    }
    /**
     * @param fileName fileName
     * @param tagName tagName
     * @return {@code fileName}<i> has been tagged as </i>{@code tagName}<i>. Cannot reapply the same tag.</i>
     * @see AddContentTagAction
     */
    static String AddContentTagAction_tagExists(Object fileName, Object tagName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddContentTagAction.tagExists", fileName, tagName);
    }
    /**
     * @return <i>Tagging Error</i>
     * @see AddContentTagAction
     */
    static String AddContentTagAction_taggingErr() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddContentTagAction.taggingErr");
    }
    /**
     * @param fileName fileName
     * @return <i>Unable to tag </i>{@code fileName}<i>, not a regular file.</i>
     * @see AddContentTagAction
     */
    static String AddContentTagAction_unableToTag_msg(Object fileName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddContentTagAction.unableToTag.msg", fileName);
    }
    /**
     * @param fileName fileName
     * @return <i>Unable to tag </i>{@code fileName}<i>.</i>
     * @see AddContentTagAction
     */
    static String AddContentTagAction_unableToTag_msg2(Object fileName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddContentTagAction.unableToTag.msg2", fileName);
    }
    /**
     * @return <i>Thread Dump</i>
     * @see ThreadDumpAction
     */
    static String CTL_DumpThreadAction() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CTL_DumpThreadAction");
    }
    /**
     * @return <i>Ingest Status Details</i>
     * @see ShowIngestProgressSnapshotAction
     */
    static String CTL_ShowIngestProgressSnapshotAction() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CTL_ShowIngestProgressSnapshotAction");
    }
    /**
     * @return <i>Remove Selected Tag(s)</i>
     * @see DeleteBlackboardArtifactTagAction
     */
    static String DeleteBlackboardArtifactTagAction_deleteTag() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DeleteBlackboardArtifactTagAction.deleteTag");
    }
    /**
     * @return <i>Tag Deletion Error</i>
     * @see DeleteBlackboardArtifactTagAction
     */
    static String DeleteBlackboardArtifactTagAction_tagDelErr() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DeleteBlackboardArtifactTagAction.tagDelErr");
    }
    /**
     * @param tagName tagName
     * @return <i>Unable to delete tag </i>{@code tagName}<i>.</i>
     * @see DeleteBlackboardArtifactTagAction
     */
    static String DeleteBlackboardArtifactTagAction_unableToDelTag_msg(Object tagName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DeleteBlackboardArtifactTagAction.unableToDelTag.msg", tagName);
    }
    /**
     * @return <i>Remove Selected Tag(s)</i>
     * @see DeleteContentTagAction
     */
    static String DeleteContentTagAction_deleteTag() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DeleteContentTagAction.deleteTag");
    }
    /**
     * @return <i>Tag Deletion Error</i>
     * @see DeleteContentTagAction
     */
    static String DeleteContentTagAction_tagDelErr() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DeleteContentTagAction.tagDelErr");
    }
    /**
     * @param tagName tagName
     * @return <i>Unable to delete tag </i>{@code tagName}<i>.</i>
     * @see DeleteContentTagAction
     */
    static String DeleteContentTagAction_unableToDelTag_msg(Object tagName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DeleteContentTagAction.unableToDelTag.msg", tagName);
    }
    /**
     * @return <i>Remove Result Tag</i>
     * @see DeleteFileBlackboardArtifactTagAction
     */
    static String DeleteFileBlackboardArtifactTagAction_deleteTag() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DeleteFileBlackboardArtifactTagAction.deleteTag");
    }
    /**
     * @param artifactID artifactID
     * @return <i>Unable to untag artifact </i>{@code artifactID}<i>.</i>
     * @see DeleteFileBlackboardArtifactTagAction
     */
    static String DeleteFileBlackboardArtifactTagAction_deleteTag_alert(Object artifactID) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DeleteFileBlackboardArtifactTagAction.deleteTag.alert", artifactID);
    }
    /**
     * @param artifactID artifactID
     * @return <i>Unable to untag artifact </i>{@code artifactID}<i>.</i>
     * @see DeleteFileBlackboardArtifactTagAction
     */
    static String DeleteFileBlackboardArtifactTagAction_deleteTags_alert(Object artifactID) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DeleteFileBlackboardArtifactTagAction.deleteTags.alert", artifactID);
    }
    /**
     * @return <i>Remove File Tag</i>
     * @see DeleteFileContentTagAction
     */
    static String DeleteFileContentTagAction_deleteTag() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DeleteFileContentTagAction.deleteTag");
    }
    /**
     * @param fileID fileID
     * @return <i>Unable to untag file </i>{@code fileID}<i>.</i>
     * @see DeleteFileContentTagAction
     */
    static String DeleteFileContentTagAction_deleteTag_alert(Object fileID) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DeleteFileContentTagAction.deleteTag.alert", fileID);
    }
    /**
     * @return <i>Ingest is running, are you sure you want to exit?</i>
     * @see ExitAction
     */
    static String ExitAction_confirmationDialog_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExitAction.confirmationDialog.message");
    }
    /**
     * @return <i>Ingest is Running</i>
     * @see ExitAction
     */
    static String ExitAction_confirmationDialog_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExitAction.confirmationDialog.title");
    }
    /**
     * @param exception_message exception message
     * @return <i>Error closing case: </i>{@code exception_message}
     * @see ExitAction
     */
    static String ExitAction_messageBox_caseCloseExceptionMessage(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExitAction.messageBox.caseCloseExceptionMessage", exception_message);
    }
    /**
     * @return <i>Description:</i>
     * @see GetTagNameDialog
     */
    static String GetTagNameDialog_descriptionLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GetTagNameDialog.descriptionLabel.text");
    }
    /**
     * @return <i>Tag indicates item is notable.</i>
     * @see GetTagNameDialog
     */
    static String GetTagNameDialog_notableCheckbox_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GetTagNameDialog.notableCheckbox.text");
    }
    /**
     * @return <i>Tag descriptions may not contain commas (,) or semicolons (;)</i>
     * @see GetTagNameDialog
     */
    static String GetTagNameDialog_tagDescriptionIllegalCharacters_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GetTagNameDialog.tagDescriptionIllegalCharacters.message");
    }
    /**
     * @return <i>Invalid character in tag description</i>
     * @see GetTagNameDialog
     */
    static String GetTagNameDialog_tagDescriptionIllegalCharacters_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GetTagNameDialog.tagDescriptionIllegalCharacters.title");
    }
    /**
     * @return <i>Tag name must be unique. A tag with this name already exists.</i>
     * @see GetTagNameDialog
     */
    static String GetTagNameDialog_tagNameAlreadyExists_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GetTagNameDialog.tagNameAlreadyExists.message");
    }
    /**
     * @return <i>Duplicate Tag Name</i>
     * @see GetTagNameDialog
     */
    static String GetTagNameDialog_tagNameAlreadyExists_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GetTagNameDialog.tagNameAlreadyExists.title");
    }
    /**
     * @param old_tag_name old tag name
     * @param artifactID artifactID
     * @return <i>Unable to replace tag </i>{@code old_tag_name}<i> for artifact </i>{@code artifactID}<i>.</i>
     * @see ReplaceBlackboardArtifactTagAction
     */
    static String ReplaceBlackboardArtifactTagAction_replaceTag_alert(Object old_tag_name, Object artifactID) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReplaceBlackboardArtifactTagAction.replaceTag.alert", old_tag_name, artifactID);
    }
    /**
     * @param old_tag_name old tag name
     * @param content_obj_id content obj id
     * @return <i>Unable to replace tag </i>{@code old_tag_name}<i> for </i>{@code content_obj_id}<i>.</i>
     * @see ReplaceContentTagAction
     */
    static String ReplaceContentTagAction_replaceTag_alert(Object old_tag_name, Object content_obj_id) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReplaceContentTagAction.replaceTag.alert", old_tag_name, content_obj_id);
    }
    /**
     * @return <i>Replace Selected Tag(s) With</i>
     * @see ReplaceTagAction
     */
    static String ReplaceTagAction_replaceTag() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReplaceTagAction.replaceTag");
    }
    private Bundle() {}
}
