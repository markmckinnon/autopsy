package org.sleuthkit.autopsy.logicalimager.dsp;
/** Localizable strings for {@link org.sleuthkit.autopsy.logicalimager.dsp}. */
class Bundle {
    /**
     * @return <i>Add image cancelled</i>
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_addImageCancelled() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.addImageCancelled");
    }
    /**
     * @param file_number file number
     * @param total_files total files
     * @return <i>Adding extracted files (</i>{@code file_number}<i>/</i>{@code total_files}<i>)</i>
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_addingExtractedFile(Object file_number, Object total_files) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.addingExtractedFile", file_number, total_files);
    }
    /**
     * @return <i>Adding extracted files</i>
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_addingExtractedFiles() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.addingExtractedFiles");
    }
    /**
     * @param file_number file number
     * @param total_files total files
     * @return <i>Adding interesting files (</i>{@code file_number}<i>/</i>{@code total_files}<i>)</i>
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_addingInterestingFile(Object file_number, Object total_files) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.addingInterestingFile", file_number, total_files);
    }
    /**
     * @return <i>Adding search results as interesting files</i>
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_addingInterestingFiles() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.addingInterestingFiles");
    }
    /**
     * @param file file
     * @return <i>Adding </i>{@code file}<i> to report</i>
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_addingToReport(Object file) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.addingToReport", file);
    }
    /**
     * @param target_image_path target image path
     * @return <i>Cannot find obj_id in tsk_image_names for </i>{@code target_image_path}
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_cannotFindDataSourceObjId(Object target_image_path) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.cannotFindDataSourceObjId", target_image_path);
    }
    /**
     * @param SearchResults_txt SearchResults.txt
     * @param directory directory
     * @return <i>Cannot find </i>{@code SearchResults_txt}<i> in </i>{@code directory}
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_cannotFindFiles(Object SearchResults_txt, Object directory) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.cannotFindFiles", SearchResults_txt, directory);
    }
    /**
     * @param src src
     * @param dest dest
     * @return <i>Copying image from </i>{@code src}<i> to </i>{@code dest}
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_copyingImageFromTo(Object src, Object dest) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.copyingImageFromTo", src, dest);
    }
    /**
     * @param sparseImageDirectory sparseImageDirectory
     * @return <i>Directory </i>{@code sparseImageDirectory}<i> does not contain any images</i>
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_directoryDoesNotContainSparseImage(Object sparseImageDirectory) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.directoryDoesNotContainSparseImage", sparseImageDirectory);
    }
    /**
     * @return <i>Done adding extracted files</i>
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_doneAddingExtractedFiles() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.doneAddingExtractedFiles");
    }
    /**
     * @return <i>Done adding search results as interesting files</i>
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_doneAddingInterestingFiles() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.doneAddingInterestingFiles");
    }
    /**
     * @param file file
     * @return <i>Done adding </i>{@code file}<i> to report</i>
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_doneAddingToReport(Object file) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.doneAddingToReport", file);
    }
    /**
     * @return <i>Done copying</i>
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_doneCopying() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.doneCopying");
    }
    /**
     * @param file file
     * @return <i>Fail to get canonical path for </i>{@code file}
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_failToGetCanonicalPath(Object file) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.failToGetCanonicalPath", file);
    }
    /**
     * @param reason reason
     * @return <i>Failed to add interesting files: </i>{@code reason}
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_failedToAddInterestingFiles(Object reason) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.failedToAddInterestingFiles", reason);
    }
    /**
     * @param file file
     * @param exception_message exception message
     * @return <i>Failed to add report </i>{@code file}<i>. Reason= </i>{@code exception_message}
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_failedToAddReport(Object file, Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.failedToAddReport", file, exception_message);
    }
    /**
     * @param src src
     * @param dest dest
     * @return <i>Failed to copy directory </i>{@code src}<i> to </i>{@code dest}
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_failedToCopyDirectory(Object src, Object dest) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.failedToCopyDirectory", src, dest);
    }
    /**
     * @param reason reason
     * @return <i>Failed to get total files count: </i>{@code reason}
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_failedToGetTotalFilesCount(Object reason) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.failedToGetTotalFilesCount", reason);
    }
    /**
     * @return <i>Ingestion cancelled</i>
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_ingestionCancelled() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.ingestionCancelled");
    }
    /**
     * @return <i>Logical Imager results</i>
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_logicalImagerResults() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.logicalImagerResults");
    }
    /**
     * @return <i>No current case</i>
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_noCurrentCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.noCurrentCase");
    }
    /**
     * @param line_number line number
     * @param fields_length fields length
     * @param expected_length expected length
     * @return <i>File does not contain enough fields at line </i>{@code line_number}<i>, got </i>{@code fields_length}<i>, expecting </i>{@code expected_length}
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_notEnoughFields(Object line_number, Object fields_length, Object expected_length) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.notEnoughFields", line_number, fields_length, expected_length);
    }
    /**
     * @param file_number file number
     * @param total_files total files
     * @return <i>Searching for interesting files (</i>{@code file_number}<i>/</i>{@code total_files}<i>)</i>
     * @see AddLogicalImageTask
     */
    static String AddLogicalImageTask_searchingInterestingFile(Object file_number, Object total_files) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddLogicalImageTask.searchingInterestingFile", file_number, total_files);
    }
    /**
     * @param imageFilePath imageFilePath
     * @return <i>Adding: </i>{@code imageFilePath}
     * @see AddMultipleImagesTask
     */
    static String AddMultipleImagesTask_adding(Object imageFilePath) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddMultipleImagesTask.adding", imageFilePath);
    }
    /**
     * @param file file
     * @return <i>Adding: </i>{@code file}<i> as an unallocated space file.</i>
     * @see AddMultipleImagesTask
     */
    static String AddMultipleImagesTask_addingFileAsLogicalFile(Object file) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddMultipleImagesTask.addingFileAsLogicalFile", file);
    }
    /**
     * @return <i>Cancellation: Add image process reverted</i>
     * @see AddMultipleImagesTask
     */
    static String AddMultipleImagesTask_cancelled() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddMultipleImagesTask.cancelled");
    }
    /**
     * @param imageFilePath imageFilePath
     * @param deviceId deviceId
     * @param exceptionMessage exceptionMessage
     * @return <i>Critical error adding </i>{@code imageFilePath}<i> for device </i>{@code deviceId}<i>: </i>{@code exceptionMessage}
     * @see AddMultipleImagesTask
     */
    static String AddMultipleImagesTask_criticalErrorAdding(Object imageFilePath, Object deviceId, Object exceptionMessage) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddMultipleImagesTask.criticalErrorAdding", imageFilePath, deviceId, exceptionMessage);
    }
    /**
     * @param imageFilePath imageFilePath
     * @param deviceId deviceId
     * @param exceptionMessage exceptionMessage
     * @return <i>Critical error reverting add image process for </i>{@code imageFilePath}<i> for device </i>{@code deviceId}<i>: </i>{@code exceptionMessage}
     * @see AddMultipleImagesTask
     */
    static String AddMultipleImagesTask_criticalErrorReverting(Object imageFilePath, Object deviceId, Object exceptionMessage) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddMultipleImagesTask.criticalErrorReverting", imageFilePath, deviceId, exceptionMessage);
    }
    /**
     * @param deviceId deviceId
     * @param exceptionMessage exceptionMessage
     * @return <i>Error adding images without file systems for device </i>{@code deviceId}<i>: </i>{@code exceptionMessage}
     * @see AddMultipleImagesTask
     */
    static String AddMultipleImagesTask_errorAddingImgWithoutFileSystem(Object deviceId, Object exceptionMessage) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddMultipleImagesTask.errorAddingImgWithoutFileSystem", deviceId, exceptionMessage);
    }
    /**
     * @return <i>Cannot determine file system type</i>
     * @see AddMultipleImagesTask
     */
    static String AddMultipleImagesTask_fsTypeUnknownErr() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddMultipleImagesTask.fsTypeUnknownErr");
    }
    /**
     * @param image_path image path
     * @return <i>Error adding image </i>{@code image_path}<i> to the database</i>
     * @see AddMultipleImagesTask
     */
    static String AddMultipleImagesTask_imageError(Object image_path) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddMultipleImagesTask.imageError", image_path);
    }
    /**
     * @param imageFilePath imageFilePath
     * @param deviceId deviceId
     * @param exceptionMessage exceptionMessage
     * @return <i>Non-critical error adding </i>{@code imageFilePath}<i> for device </i>{@code deviceId}<i>: </i>{@code exceptionMessage}
     * @see AddMultipleImagesTask
     */
    static String AddMultipleImagesTask_nonCriticalErrorAdding(Object imageFilePath, Object deviceId, Object exceptionMessage) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddMultipleImagesTask.nonCriticalErrorAdding", imageFilePath, deviceId, exceptionMessage);
    }
    /**
     * @return <i>Autopsy Logical Imager Results</i>
     * @see LogicalImagerDSProcessor
     */
    static String LogicalImagerDSProcessor_dataSourceType() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalImagerDSProcessor.dataSourceType");
    }
    /**
     * @return <i>Destination directory confirmation</i>
     * @see LogicalImagerDSProcessor
     */
    static String LogicalImagerDSProcessor_destinationDirectoryConfirmation() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalImagerDSProcessor.destinationDirectoryConfirmation");
    }
    /**
     * @param directory directory
     * @return <i>The logical imager folder </i>{@code directory}<i> already exists,<br>do you want to add it again using a new folder name?</i>
     * @see LogicalImagerDSProcessor
     */
    static String LogicalImagerDSProcessor_destinationDirectoryConfirmationMsg(Object directory) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalImagerDSProcessor.destinationDirectoryConfirmationMsg", directory);
    }
    /**
     * @param directory directory
     * @return <i>Directory </i>{@code directory}<i> already exists</i>
     * @see LogicalImagerDSProcessor
     */
    static String LogicalImagerDSProcessor_directoryAlreadyExists(Object directory) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalImagerDSProcessor.directoryAlreadyExists", directory);
    }
    /**
     * @param directory directory
     * @return <i>Failed to create directory </i>{@code directory}
     * @see LogicalImagerDSProcessor
     */
    static String LogicalImagerDSProcessor_failToCreateDirectory(Object directory) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalImagerDSProcessor.failToCreateDirectory", directory);
    }
    /**
     * @param imageDirPath imageDirPath
     * @return {@code imageDirPath}<i> not found.<br>USB drive has been ejected.</i>
     * @see LogicalImagerDSProcessor
     */
    static String LogicalImagerDSProcessor_imageDirPathNotFound(Object imageDirPath) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalImagerDSProcessor.imageDirPathNotFound", imageDirPath);
    }
    /**
     * @return <i>No current case</i>
     * @see LogicalImagerDSProcessor
     */
    static String LogicalImagerDSProcessor_noCurrentCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalImagerDSProcessor.noCurrentCase");
    }
    /**
     * @return <i>Hostname</i>
     * @see LogicalImagerPanel
     */
    static String LogicalImagerPanel_imageTable_columnModel_title0() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalImagerPanel.imageTable.columnModel.title0");
    }
    /**
     * @return <i>Extracted Date (GMT)</i>
     * @see LogicalImagerPanel
     */
    static String LogicalImagerPanel_imageTable_columnModel_title1() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalImagerPanel.imageTable.columnModel.title1");
    }
    /**
     * @return <i>Path</i>
     * @see LogicalImagerPanel
     */
    static String LogicalImagerPanel_imageTable_columnModel_title2() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalImagerPanel.imageTable.columnModel.title2");
    }
    /**
     * @param sparseImageDirectory sparseImageDirectory
     * @return <i>Directory </i>{@code sparseImageDirectory}<i> does not contain any images</i>
     * @see LogicalImagerPanel
     */
    static String LogicalImagerPanel_messageLabel_directoryDoesNotContainSparseImage(Object sparseImageDirectory) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalImagerPanel.messageLabel.directoryDoesNotContainSparseImage", sparseImageDirectory);
    }
    /**
     * @param invalidFormatDirectory invalidFormatDirectory
     * @return <i>Directory </i>{@code invalidFormatDirectory}<i> does not match format Logical_Imager_HOSTNAME_yyyymmdd_HH_MM_SS</i>
     * @see LogicalImagerPanel
     */
    static String LogicalImagerPanel_messageLabel_directoryFormatInvalid(Object invalidFormatDirectory) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalImagerPanel.messageLabel.directoryFormatInvalid", invalidFormatDirectory);
    }
    /**
     * @return <i>Drive has no images</i>
     * @see LogicalImagerPanel
     */
    static String LogicalImagerPanel_messageLabel_driveHasNoImages() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalImagerPanel.messageLabel.driveHasNoImages");
    }
    /**
     * @return <i>No drive found</i>
     * @see LogicalImagerPanel
     */
    static String LogicalImagerPanel_messageLabel_noExternalDriveFound() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalImagerPanel.messageLabel.noExternalDriveFound");
    }
    /**
     * @return <i>No image selected</i>
     * @see LogicalImagerPanel
     */
    static String LogicalImagerPanel_messageLabel_noImageSelected() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalImagerPanel.messageLabel.noImageSelected");
    }
    /**
     * @return <i>Scanning external drives for images ...</i>
     * @see LogicalImagerPanel
     */
    static String LogicalImagerPanel_messageLabel_scanningExternalDrives() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalImagerPanel.messageLabel.scanningExternalDrives");
    }
    /**
     * @return <i>Select acquisition from Drive</i>
     * @see LogicalImagerPanel
     */
    static String LogicalImagerPanel_selectAcquisitionFromDriveLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalImagerPanel.selectAcquisitionFromDriveLabel.text");
    }
    private Bundle() {}
}
