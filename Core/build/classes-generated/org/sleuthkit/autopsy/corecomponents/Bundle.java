package org.sleuthkit.autopsy.corecomponents;
/** Localizable strings for {@link org.sleuthkit.autopsy.corecomponents}. */
class Bundle {
    /**
     * @return <i>Please select a path with no quotes.</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOPtionsPanel_isHeapPathValid_illegalCharacters() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOPtionsPanel_isHeapPathValid_illegalCharacters");
    }
    /**
     * @return <i>Invalid image file specified.</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_agencyLogoPathFieldValidationLabel_invalidImageSpecified_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel.agencyLogoPathFieldValidationLabel.invalidImageSpecified.text");
    }
    /**
     * @return <i>Path is not valid.</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_agencyLogoPathFieldValidationLabel_invalidPath_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel.agencyLogoPathFieldValidationLabel.invalidPath.text");
    }
    /**
     * @return <i>Agency logo path must be set.</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_agencyLogoPathFieldValidationLabel_pathNotSet_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel.agencyLogoPathFieldValidationLabel.pathNotSet.text");
    }
    /**
     * @return <i>File already exists.  Please select a new location.</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_heapDumpBrowseButtonActionPerformed_fileAlreadyExistsMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel_heapDumpBrowseButtonActionPerformed_fileAlreadyExistsMessage");
    }
    /**
     * @return <i>File Already Exists</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_heapDumpBrowseButtonActionPerformed_fileAlreadyExistsTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel_heapDumpBrowseButtonActionPerformed_fileAlreadyExistsTitle");
    }
    /**
     * @return <i>The selected file was not able to be used as an agency logo.</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_invalidImageFile_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel.invalidImageFile.msg");
    }
    /**
     * @return <i>Invalid Image File</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_invalidImageFile_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel.invalidImageFile.title");
    }
    /**
     * @return <i>Cannot change heap dump path while in developer mode.</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_isHeapPathValid_developerMode() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel_isHeapPathValid_developerMode");
    }
    /**
     * @return <i>Changing heap dump path settings only enabled for 64 bit version.</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_isHeapPathValid_not64BitMachine() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel_isHeapPathValid_not64BitMachine");
    }
    /**
     * @return <i>Please select an existing directory.</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_isHeapPathValid_selectValidDirectory() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel_isHeapPathValid_selectValidDirectory");
    }
    /**
     * @return <i>A positive integer is required here.</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_logNumAlert_invalidInput_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel.logNumAlert.invalidInput.text");
    }
    /**
     * @return <i>Memory settings are not available while running in developer mode</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_memFieldValidationLabel_developerMode_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel.memFieldValidationLabel.developerMode.text");
    }
    /**
     * @return <i>Invalid characters, value must be a positive integer</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_memFieldValidationLabel_invalidCharacters_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel.memFieldValidationLabel.invalidCharacters.text");
    }
    /**
     * @return <i>No value entered</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_memFieldValidationLabel_noValueEntered_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel.memFieldValidationLabel.noValueEntered.text");
    }
    /**
     * @return <i>JVM memory settings only enabled for 64 bit version</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_memFieldValidationLabel_not64BitInstall_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel.memFieldValidationLabel.not64BitInstall.text");
    }
    /**
     * @param systemMemory systemMemory
     * @return <i>Value must be less than the total system memory of </i>{@code systemMemory}<i>GB</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_memFieldValidationLabel_overMaxMemory_text(Object systemMemory) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel.memFieldValidationLabel.overMaxMemory.text", systemMemory);
    }
    /**
     * @param minimumMemory minimumMemory
     * @return <i>Value must be at least </i>{@code minimumMemory}<i>GB</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_memFieldValidationLabel_underMinMemory_text(Object minimumMemory) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel.memFieldValidationLabel.underMinMemory.text", minimumMemory);
    }
    /**
     * @return <i>There was an error updating temporary directory choice selection.</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_storeTempDir_onChoiceError_description() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel_storeTempDir_onChoiceError_description");
    }
    /**
     * @return <i>Error Saving Temporary Directory Choice</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_storeTempDir_onChoiceError_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel_storeTempDir_onChoiceError_title");
    }
    /**
     * @param path path
     * @return <i>There was an error creating the temporary directory on the filesystem at: </i>{@code path}<i>.</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_storeTempDir_onError_description(Object path) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel_storeTempDir_onError_description", path);
    }
    /**
     * @return <i>Error Saving Temporary Directory</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_storeTempDir_onError_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel_storeTempDir_onError_title");
    }
    /**
     * @param path path
     * @return <i>Unable to create temporary directory within specified path: </i>{@code path}
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_tempDirectoryBrowseButtonActionPerformed_onInvalidPath_description(Object path) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel_tempDirectoryBrowseButtonActionPerformed_onInvalidPath_description", path);
    }
    /**
     * @return <i>Path cannot be used</i>
     * @see AutopsyOptionsPanel
     */
    static String AutopsyOptionsPanel_tempDirectoryBrowseButtonActionPerformed_onInvalidPath_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AutopsyOptionsPanel_tempDirectoryBrowseButtonActionPerformed_onInvalidPath_title");
    }
    /**
     * @return <i>Offline Autopsy Documentation</i>
     * @see OfflineHelpAction
     */
    static String CTL_OfflineHelpAction() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CTL_OfflineHelpAction");
    }
    /**
     * @return <i>Online Autopsy Documentation</i>
     * @see OnlineHelpAction
     */
    static String CTL_OnlineHelpAction() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CTL_OnlineHelpAction");
    }
    /**
     * @return <i>Failed to get some or all attributes from case database</i>
     * @see DataArtifactContentViewer
     */
    static String DataArtifactContentViewer_failedToGetAttributes_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataArtifactContentViewer.failedToGetAttributes.message");
    }
    /**
     * @return <i>Failed to get source file path from case database</i>
     * @see DataArtifactContentViewer
     */
    static String DataArtifactContentViewer_failedToGetSourcePath_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataArtifactContentViewer.failedToGetSourcePath.message");
    }
    /**
     * @return <i>Copying file to open in HxD...</i>
     * @see DataContentViewerHex
     */
    static String DataContentViewerHex_copyingFile() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataContentViewerHex.copyingFile");
    }
    /**
     * @return <i>Unable to launch HxD Editor. Please specify the HxD install location in Tools -> Options -> External Viewer</i>
     * @see DataContentViewerHex
     */
    static String DataContentViewerHex_launchError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataContentViewerHex.launchError");
    }
    /**
     * @return <i>Loading hex from file...</i>
     * @see DataContentViewerHex
     */
    static String DataContentViewerHex_loading_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataContentViewerHex_loading_text");
    }
    /**
     * @return <i>C</i>
     * @see DataResultViewerTable
     */
    static String DataResultViewerTable_commentRender_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultViewerTable.commentRender.name");
    }
    /**
     * @return <i>C(omments) indicates whether the item has a comment</i>
     * @see DataResultViewerTable
     */
    static String DataResultViewerTable_commentRender_toolTip() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultViewerTable.commentRender.toolTip");
    }
    /**
     * @return <i>Comments exist both in Central Repository and on associated tag(s)</i>
     * @see DataResultViewerTable
     */
    static String DataResultViewerTable_commentRenderer_crAndTagComment_toolTip() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultViewerTable.commentRenderer.crAndTagComment.toolTip");
    }
    /**
     * @return <i>Comment exists in Central Repository</i>
     * @see DataResultViewerTable
     */
    static String DataResultViewerTable_commentRenderer_crComment_toolTip() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultViewerTable.commentRenderer.crComment.toolTip");
    }
    /**
     * @return <i>No comments found</i>
     * @see DataResultViewerTable
     */
    static String DataResultViewerTable_commentRenderer_noComment_toolTip() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultViewerTable.commentRenderer.noComment.toolTip");
    }
    /**
     * @return <i>Comment exists on associated tag(s)</i>
     * @see DataResultViewerTable
     */
    static String DataResultViewerTable_commentRenderer_tagComment_toolTip() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultViewerTable.commentRenderer.tagComment.toolTip");
    }
    /**
     * @return <i>O</i>
     * @see DataResultViewerTable
     */
    static String DataResultViewerTable_countRender_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultViewerTable.countRender.name");
    }
    /**
     * @return <i>O(ccurrences) indicates the number of data sources containing the item in the Central Repository</i>
     * @see DataResultViewerTable
     */
    static String DataResultViewerTable_countRender_toolTip() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultViewerTable.countRender.toolTip");
    }
    /**
     * @return <i>No data to export</i>
     * @see DataResultViewerTable
     */
    static String DataResultViewerTable_exportCSVButtonActionPerformed_empty() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultViewerTable.exportCSVButtonActionPerformed.empty");
    }
    /**
     * @return <i>Name</i>
     * @see DataResultViewerTable
     */
    static String DataResultViewerTable_firstColLbl() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultViewerTable.firstColLbl");
    }
    /**
     * @return <i>Invalid page number</i>
     * @see DataResultViewerTable
     */
    static String DataResultViewerTable_goToPageTextField_err() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultViewerTable.goToPageTextField.err");
    }
    /**
     * @param totalPages totalPages
     * @return <i>Please enter a valid page number between 1 and </i>{@code totalPages}
     * @see DataResultViewerTable
     */
    static String DataResultViewerTable_goToPageTextField_msgDlg(Object totalPages) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultViewerTable.goToPageTextField.msgDlg", totalPages);
    }
    /**
     * @param currentPage currentPage
     * @param totalPages totalPages
     * @return {@code currentPage}<i> of </i>{@code totalPages}
     * @see DataResultViewerTable
     */
    static String DataResultViewerTable_pageNumbers_curOfTotal(Object currentPage, Object totalPages) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultViewerTable.pageNumbers.curOfTotal", currentPage, totalPages);
    }
    /**
     * @return <i>S</i>
     * @see DataResultViewerTable
     */
    static String DataResultViewerTable_scoreRender_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultViewerTable.scoreRender.name");
    }
    /**
     * @return <i>S(core) indicates whether the item is interesting or notable</i>
     * @see DataResultViewerTable
     */
    static String DataResultViewerTable_scoreRender_toolTip() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultViewerTable.scoreRender.toolTip");
    }
    /**
     * @return <i>Table</i>
     * @see DataResultViewerTable
     */
    static String DataResultViewerTable_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultViewerTable.title");
    }
    /**
     * @return <i>Sorted by: ---</i>
     * @see DataResultViewerThumbnail
     */
    static String DataResultViewerThumbnail_sortLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultViewerThumbnail.sortLabel.text");
    }
    /**
     * @param sort_criteria sort criteria
     * @return <i>Sorted by: </i>{@code sort_criteria}
     * @see DataResultViewerThumbnail
     */
    static String DataResultViewerThumbnail_sortLabel_textTemplate(Object sort_criteria) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultViewerThumbnail.sortLabel.textTemplate", sort_criteria);
    }
    /**
     * @return <i>Large Thumbnails</i>
     * @see DataResultViewerThumbnail
     */
    static String DataResultViewerThumbnail_thumbnailSizeComboBox_large() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultViewerThumbnail.thumbnailSizeComboBox.large");
    }
    /**
     * @return <i>Medium Thumbnails</i>
     * @see DataResultViewerThumbnail
     */
    static String DataResultViewerThumbnail_thumbnailSizeComboBox_medium() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultViewerThumbnail.thumbnailSizeComboBox.medium");
    }
    /**
     * @return <i>Small Thumbnails</i>
     * @see DataResultViewerThumbnail
     */
    static String DataResultViewerThumbnail_thumbnailSizeComboBox_small() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultViewerThumbnail.thumbnailSizeComboBox.small");
    }
    /**
     * @return <i>Close case to modfy settings</i>
     * @see MultiUserSettingsPanel
     */
    static String MultiUserSettingsPanel_Close_Case_To_Modify() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MultiUserSettingsPanel_Close_Case_To_Modify");
    }
    /**
     * @return <i>Choose Sort Criteria</i>
     * @see SortChooser
     */
    static String SortChooser_dialogTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SortChooser.dialogTitle");
    }
    /**
     * @return <i>(Cancelling)</i>
     * @see ThumbnailViewChildren
     */
    static String ThumbnailViewChildren_progress_cancelling() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ThumbnailViewChildren.progress.cancelling");
    }
    /**
     * @param file_name file name
     * @return <i>Generating thumbnail for </i>{@code file_name}
     * @see ThumbnailViewChildren
     */
    static String ThumbnailViewNode_progressHandle_text(Object file_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ThumbnailViewNode.progressHandle.text", file_name);
    }
    /**
     * @return <i>Error processing value changes.</i>
     * @see ViewPreferencesPanelController
     */
    static String ViewOptionsController_moduleErr() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewOptionsController.moduleErr");
    }
    /**
     * @return <i>Value change processing failed.</i>
     * @see ViewPreferencesPanelController
     */
    static String ViewOptionsController_moduleErr_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewOptionsController.moduleErr.msg");
    }
    private Bundle() {}
}
