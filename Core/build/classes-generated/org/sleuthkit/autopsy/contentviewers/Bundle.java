package org.sleuthkit.autopsy.contentviewers;
/** Localizable strings for {@link org.sleuthkit.autopsy.contentviewers}. */
class Bundle {
    /**
     * @return <i>Application</i>
     * @see FileViewer
     */
    static String ApplicationContentViewer_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ApplicationContentViewer.title");
    }
    /**
     * @return <i>Displays file contents.</i>
     * @see FileViewer
     */
    static String ApplicationContentViewer_toolTip() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ApplicationContentViewer.toolTip");
    }
    /**
     * @return <i>No open case available.</i>
     * @see MediaPlayerPanel
     */
    static String GstVideoPanel_noOpenCase_errMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GstVideoPanel.noOpenCase.errMsg");
    }
    /**
     * @return <i>Hide Images</i>
     * @see HtmlPanel
     */
    static String HtmlPanel_showImagesToggleButton_hide() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HtmlPanel_showImagesToggleButton_hide");
    }
    /**
     * @return <i>Download Images</i>
     * @see HtmlPanel
     */
    static String HtmlPanel_showImagesToggleButton_show() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HtmlPanel_showImagesToggleButton_show");
    }
    /**
     * @return <i>This file has unsupported encoding</i>
     * @see HtmlViewer
     */
    static String HtmlViewer_encoding_error() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HtmlViewer_encoding_error");
    }
    /**
     * @return <i>This file is missing or unreadable.</i>
     * @see HtmlViewer
     */
    static String HtmlViewer_file_error() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HtmlViewer_file_error");
    }
    /**
     * @return <i>The HTML text cannot be displayed, it may not be correctly formed HTML.</i>
     * @see HtmlPanel
     */
    static String Html_text_display_error() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Html_text_display_error");
    }
    /**
     * @return <i>File not supported.</i>
     * @see MediaPlayerPanel
     */
    static String MediaPlayerPanel_noSupport() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MediaPlayerPanel.noSupport");
    }
    /**
     * @return <i>A problem was encountered with the video and audio playback service. Video and audio playback will be disabled for the remainder of the session.</i>
     * @see MediaPlayerPanel
     */
    static String MediaPlayerPanel_playbackDisabled() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MediaPlayerPanel.playbackDisabled");
    }
    /**
     * @return <i>%02d:%02d:%02d</i>
     * @see MediaPlayerPanel
     */
    static String MediaPlayerPanel_timeFormat() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MediaPlayerPanel.timeFormat");
    }
    /**
     * @return <i>Unknown</i>
     * @see MediaPlayerPanel
     */
    static String MediaPlayerPanel_unknownTime() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MediaPlayerPanel.unknownTime");
    }
    /**
     * @return <i>Create</i>
     * @see MediaViewImagePanel
     */
    static String MediaViewImagePanel_createTagOption() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MediaViewImagePanel.createTagOption");
    }
    /**
     * @return <i>Delete</i>
     * @see MediaViewImagePanel
     */
    static String MediaViewImagePanel_deleteTagOption() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MediaViewImagePanel.deleteTagOption");
    }
    /**
     * @return <i>Could not load file into Media View: insufficent memory.</i>
     * @see MediaViewImagePanel
     */
    static String MediaViewImagePanel_errorLabel_OOMText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MediaViewImagePanel.errorLabel.OOMText");
    }
    /**
     * @return <i>Could not load file into Media View.</i>
     * @see MediaViewImagePanel
     */
    static String MediaViewImagePanel_errorLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MediaViewImagePanel.errorLabel.text");
    }
    /**
     * @return <i>Save</i>
     * @see MediaViewImagePanel
     */
    static String MediaViewImagePanel_exportSaveText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MediaViewImagePanel.exportSaveText");
    }
    /**
     * @return <i>Export</i>
     * @see MediaViewImagePanel
     */
    static String MediaViewImagePanel_exportTagOption() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MediaViewImagePanel.exportTagOption");
    }
    /**
     * @return <i>Open in External Viewer  Ctrl+E</i>
     * @see MediaViewImagePanel
     */
    static String MediaViewImagePanel_externalViewerButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MediaViewImagePanel.externalViewerButton.text");
    }
    /**
     * @return <i>Choose a save location</i>
     * @see MediaViewImagePanel
     */
    static String MediaViewImagePanel_fileChooserTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MediaViewImagePanel.fileChooserTitle");
    }
    /**
     * @return <i>Hide</i>
     * @see MediaViewImagePanel
     */
    static String MediaViewImagePanel_hideTagOption() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MediaViewImagePanel.hideTagOption");
    }
    /**
     * @return <i>Tagged image was successfully saved.</i>
     * @see MediaViewImagePanel
     */
    static String MediaViewImagePanel_successfulExport() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MediaViewImagePanel.successfulExport");
    }
    /**
     * @return <i>Unable to export tagged image to disk.</i>
     * @see MediaViewImagePanel
     */
    static String MediaViewImagePanel_unsuccessfulExport() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MediaViewImagePanel.unsuccessfulExport");
    }
    /**
     * @return <i>No Data</i>
     * @see Metadata
     */
    static String MetadataWorker_doInBackground_noDataMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MetadataWorker.doInBackground.noDataMsg");
    }
    /**
     * @return <i>Source File Metadata</i>
     * @see Metadata
     */
    static String Metadata_dataArtifactTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Metadata_dataArtifactTitle");
    }
    /**
     * @return <i>Metadata</i>
     * @see Metadata
     */
    static String Metadata_headerTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Metadata.headerTitle");
    }
    /**
     * @return <i>Metadata loading...</i>
     * @see Metadata
     */
    static String Metadata_nodeText_loading() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Metadata.nodeText.loading");
    }
    /**
     * @return <i>None</i>
     * @see Metadata
     */
    static String Metadata_nodeText_none() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Metadata.nodeText.none");
    }
    /**
     * @return <i>(results truncated)</i>
     * @see Metadata
     */
    static String Metadata_nodeText_truncated() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Metadata.nodeText.truncated");
    }
    /**
     * @return <i>Unknown</i>
     * @see Metadata
     */
    static String Metadata_nodeText_unknown() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Metadata.nodeText.unknown");
    }
    /**
     * @return <i>Acquisition Details</i>
     * @see Metadata
     */
    static String Metadata_tableRowTitle_acquisitionDetails() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Metadata.tableRowTitle.acquisitionDetails");
    }
    /**
     * @return <i>Device ID</i>
     * @see Metadata
     */
    static String Metadata_tableRowTitle_deviceId() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Metadata.tableRowTitle.deviceId");
    }
    /**
     * @return <i>Downloaded From</i>
     * @see Metadata
     */
    static String Metadata_tableRowTitle_downloadSource() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Metadata.tableRowTitle.downloadSource");
    }
    /**
     * @return <i>Type</i>
     * @see Metadata
     */
    static String Metadata_tableRowTitle_imageType() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Metadata.tableRowTitle.imageType");
    }
    /**
     * @return <i>MIME Type</i>
     * @see Metadata
     */
    static String Metadata_tableRowTitle_mimeType() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Metadata.tableRowTitle.mimeType");
    }
    /**
     * @return <i>Sector Size</i>
     * @see Metadata
     */
    static String Metadata_tableRowTitle_sectorSize() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Metadata.tableRowTitle.sectorSize");
    }
    /**
     * @return <i>SHA1</i>
     * @see Metadata
     */
    static String Metadata_tableRowTitle_sha1() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Metadata.tableRowTitle.sha1");
    }
    /**
     * @return <i>SHA-256</i>
     * @see Metadata
     */
    static String Metadata_tableRowTitle_sha256() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Metadata.tableRowTitle.sha256");
    }
    /**
     * @return <i>Time Zone</i>
     * @see Metadata
     */
    static String Metadata_tableRowTitle_timezone() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Metadata.tableRowTitle.timezone");
    }
    /**
     * @return <i>This document is password protected.</i>
     * @see PDFViewer
     */
    static String PDFViewer_encryptedDialog() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PDFViewer.encryptedDialog");
    }
    /**
     * @return <i>An error occurred while opening this PDF document. Check the logs for more information. You may continue to use this feature on other PDF documents.</i>
     * @see PDFViewer
     */
    static String PDFViewer_errorDialog() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PDFViewer.errorDialog");
    }
    /**
     * @return <i>Key</i>
     * @see PListViewer
     */
    static String PListNode_KeyCol() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PListNode.KeyCol");
    }
    /**
     * @return <i>Type</i>
     * @see PListViewer
     */
    static String PListNode_TypeCol() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PListNode.TypeCol");
    }
    /**
     * @return <i>Value</i>
     * @see PListViewer
     */
    static String PListNode_ValueCol() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PListNode.ValueCol");
    }
    /**
     * @return <i>Binary Data value not shown</i>
     * @see PListViewer
     */
    static String PListViewer_DataType_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PListViewer.DataType.message");
    }
    /**
     * @return <i>Plist file export failed.</i>
     * @see PListViewer
     */
    static String PListViewer_ExportFailed_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PListViewer.ExportFailed.message");
    }
    /**
     * @return <i>Plist file exported successfully</i>
     * @see PListViewer
     */
    static String PListViewer_ExportSuccess_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PListViewer.ExportSuccess.message");
    }
    /**
     * @return <i>Error while parsing/displaying plist file.</i>
     * @see PListViewer
     */
    static String PListViewer_processPlist_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PListViewer.processPlist.errorMessage");
    }
    /**
     * @return <i>Interrupted while parsing/displaying plist file.</i>
     * @see PListViewer
     */
    static String PListViewer_processPlist_interruptedMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PListViewer.processPlist.interruptedMessage");
    }
    /**
     * @return <i>Date</i>
     * @see SQLiteTableView
     */
    static String SQLiteTableView_DisplayAsMenuItem_Date() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SQLiteTableView.DisplayAsMenuItem.Date");
    }
    /**
     * @return <i>Raw Data</i>
     * @see SQLiteTableView
     */
    static String SQLiteTableView_DisplayAsMenuItem_RawData() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SQLiteTableView.DisplayAsMenuItem.RawData");
    }
    /**
     * @return <i>Display as</i>
     * @see SQLiteTableView
     */
    static String SQLiteTableView_DisplayAs_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SQLiteTableView.DisplayAs.text");
    }
    /**
     * @return <i>No tables found</i>
     * @see SQLiteViewer
     */
    static String SQLiteViewer_comboBox_noTableEntry() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SQLiteViewer.comboBox.noTableEntry");
    }
    /**
     * @return <i>Do you want to overwrite the existing file?</i>
     * @see SQLiteViewer
     */
    static String SQLiteViewer_csvExport_confirm_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SQLiteViewer.csvExport.confirm.msg");
    }
    /**
     * @return <i>Please input a file name for exporting.</i>
     * @see SQLiteViewer
     */
    static String SQLiteViewer_csvExport_fileName_empty() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SQLiteViewer.csvExport.fileName.empty");
    }
    /**
     * @return <i>Export to csv file</i>
     * @see SQLiteViewer
     */
    static String SQLiteViewer_csvExport_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SQLiteViewer.csvExport.title");
    }
    /**
     * @return <i>The file could not be extracted from the data source.</i>
     * @see SQLiteViewer
     */
    static String SQLiteViewer_errorMessage_failedToExtractFile() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SQLiteViewer.errorMessage.failedToExtractFile");
    }
    /**
     * @return <i>The database tables in the file could not be read.</i>
     * @see SQLiteViewer
     */
    static String SQLiteViewer_errorMessage_failedToQueryDatabase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SQLiteViewer.errorMessage.failedToQueryDatabase");
    }
    /**
     * @return <i>The JDBC driver for SQLite could not be loaded.</i>
     * @see SQLiteViewer
     */
    static String SQLiteViewer_errorMessage_failedToinitJDBCDriver() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SQLiteViewer.errorMessage.failedToinitJDBCDriver");
    }
    /**
     * @return <i>The processing of the file was interrupted.</i>
     * @see SQLiteViewer
     */
    static String SQLiteViewer_errorMessage_interrupted() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SQLiteViewer.errorMessage.interrupted");
    }
    /**
     * @return <i>The case has been closed.</i>
     * @see SQLiteViewer
     */
    static String SQLiteViewer_errorMessage_noCurrentCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SQLiteViewer.errorMessage.noCurrentCase");
    }
    /**
     * @param exception_message exception message
     * @return <i>An unexpected error occurred:<br>{0).</i>
     * @see SQLiteViewer
     */
    static String SQLiteViewer_errorMessage_unexpectedError(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SQLiteViewer.errorMessage.unexpectedError", exception_message);
    }
    /**
     * @return <i>File name: </i>
     * @see SQLiteViewer
     */
    static String SQLiteViewer_exportTableToCsv_FileName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SQLiteViewer.exportTableToCsv.FileName");
    }
    /**
     * @return <i>Table name: </i>
     * @see SQLiteViewer
     */
    static String SQLiteViewer_exportTableToCsv_TableName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SQLiteViewer.exportTableToCsv.TableName");
    }
    /**
     * @return <i>Failed to export table content to csv file.</i>
     * @see SQLiteViewer
     */
    static String SQLiteViewer_exportTableToCsv_write_errText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SQLiteViewer.exportTableToCsv.write.errText");
    }
    /**
     * @param tableName tableName
     * @return <i>Error getting rows for table: </i>{@code tableName}
     * @see SQLiteViewer
     */
    static String SQLiteViewer_readTable_errorText(Object tableName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SQLiteViewer.readTable.errorText", tableName);
    }
    /**
     * @param tableName tableName
     * @return <i>Error getting row count for table: </i>{@code tableName}
     * @see SQLiteViewer
     */
    static String SQLiteViewer_selectTable_errorText(Object tableName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SQLiteViewer.selectTable.errorText", tableName);
    }
    /**
     * @return <i>Original Text</i>
     * @see TranslatablePanel
     */
    static String TranslatablePanel_comboBoxOption_originalText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TranslatablePanel.comboBoxOption.originalText");
    }
    /**
     * @return <i>Translated Text</i>
     * @see TranslatablePanel
     */
    static String TranslatablePanel_comboBoxOption_translatedText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TranslatablePanel.comboBoxOption.translatedText");
    }
    /**
     * @param exception_message exception message
     * @return <i>There was an error displaying the text: </i>{@code exception_message}
     * @see TranslatablePanel
     */
    static String TranslatablePanel_onSetContentError_text(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TranslatablePanel.onSetContentError.text", exception_message);
    }
    private Bundle() {}
}
