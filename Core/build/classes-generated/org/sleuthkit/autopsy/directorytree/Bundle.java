package org.sleuthkit.autopsy.directorytree;
/** Localizable strings for {@link org.sleuthkit.autopsy.directorytree}. */
class Bundle {
    /**
     * @return <i>Error exporting to CSV file</i>
     * @see ExportCSVAction
     */
    static String CSVWriter_done_notifyMsg_error() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CSVWriter.done.notifyMsg.error");
    }
    /**
     * @param Output_file Output file
     * @return <i>Wrote to </i>{@code Output_file}
     * @see ExportCSVAction
     */
    static String CSVWriter_done_notifyMsg_success(Object Output_file) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CSVWriter.done.notifyMsg.success", Output_file);
    }
    /**
     * @return <i>Cancelling</i>
     * @see ExportCSVAction
     */
    static String CSVWriter_progress_cancelling() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CSVWriter.progress.cancelling");
    }
    /**
     * @return <i>Exporting to CSV file</i>
     * @see ExportCSVAction
     */
    static String CSVWriter_progress_extracting() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CSVWriter.progress.extracting");
    }
    /**
     * @return <i>View Source Result</i>
     * @see DataResultFilterNode
     */
    static String DataResultFilterNode_viewSourceArtifact_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataResultFilterNode.viewSourceArtifact.text");
    }
    /**
     * @param dataSourceCount dataSourceCount
     * @return <i>This case contains </i>{@code dataSourceCount}<i> data sources. Would you like to group by data source for faster loading?</i>
     * @see DirectoryTreeTopComponent
     */
    static String DirectoryTreeTopComponent_componentOpened_groupDataSources_text(Object dataSourceCount) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DirectoryTreeTopComponent.componentOpened.groupDataSources.text", dataSourceCount);
    }
    /**
     * @return <i>Group by data source?</i>
     * @see DirectoryTreeTopComponent
     */
    static String DirectoryTreeTopComponent_componentOpened_groupDataSources_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DirectoryTreeTopComponent.componentOpened.groupDataSources.title");
    }
    /**
     * @return <i>Data not available. Run file type identification module.</i>
     * @see DirectoryTreeTopComponent
     */
    static String DirectoryTreeTopComponent_emptyMimeNode_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DirectoryTreeTopComponent.emptyMimeNode.text");
    }
    /**
     * @return <i>Listing</i>
     * @see DirectoryTreeTopComponent
     */
    static String DirectoryTreeTopComponent_resultsView_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DirectoryTreeTopComponent.resultsView.title");
    }
    /**
     * @return <i>No data to export</i>
     * @see ExportCSVAction
     */
    static String ExportCSV_saveNodesToCSV_empty() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportCSV.saveNodesToCSV.empty");
    }
    /**
     * @param Output_file Output file
     * @return <i>File </i>{@code Output_file}<i> already exists</i>
     * @see ExportCSVAction
     */
    static String ExportCSV_saveNodesToCSV_fileExists(Object Output_file) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportCSV.saveNodesToCSV.fileExists", Output_file);
    }
    /**
     * @return <i>No open case available</i>
     * @see ExportCSVAction
     */
    static String ExportCSV_saveNodesToCSV_noCurrentCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportCSV.saveNodesToCSV.noCurrentCase");
    }
    /**
     * @return <i>Export Selected Rows to CSV</i>
     * @see ExportCSVAction
     */
    static String ExportCSV_title_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportCSV.title.text");
    }
    /**
     * @return <i>There is no associated editor for files of this type or the associated application failed to launch.</i>
     * @see ExternalViewerAction
     */
    static String ExternalViewerAction_actionPerformed_failure_IO_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExternalViewerAction.actionPerformed.failure.IO.message");
    }
    /**
     * @return <i>The file is an executable and will not be opened.</i>
     * @see ExternalViewerAction
     */
    static String ExternalViewerAction_actionPerformed_failure_exe_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExternalViewerAction.actionPerformed.failure.exe.message");
    }
    /**
     * @return <i>The file no longer exists.</i>
     * @see ExternalViewerAction
     */
    static String ExternalViewerAction_actionPerformed_failure_missingFile_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExternalViewerAction.actionPerformed.failure.missingFile.message");
    }
    /**
     * @return <i>Cannot open URL</i>
     * @see ExternalViewerAction
     */
    static String ExternalViewerAction_actionPerformed_failure_open_url() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExternalViewerAction.actionPerformed.failure.open.url");
    }
    /**
     * @return <i>Permission to open the file was denied.</i>
     * @see ExternalViewerAction
     */
    static String ExternalViewerAction_actionPerformed_failure_permission_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExternalViewerAction.actionPerformed.failure.permission.message");
    }
    /**
     * @return <i>This platform (operating system) does not support opening a file in an editor this way.</i>
     * @see ExternalViewerAction
     */
    static String ExternalViewerAction_actionPerformed_failure_support_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExternalViewerAction.actionPerformed.failure.support.message");
    }
    /**
     * @param file_name file name
     * @return <i>Open File Failure </i>{@code file_name}
     * @see ExternalViewerAction
     */
    static String ExternalViewerAction_actionPerformed_failure_title(Object file_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExternalViewerAction.actionPerformed.failure.title", file_name);
    }
    /**
     * @return <i>Open URL Failure</i>
     * @see ExternalViewerAction
     */
    static String ExternalViewerAction_actionPerformed_urlFailure_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExternalViewerAction.actionPerformed.urlFailure.title");
    }
    /**
     * @return <i>Open in External Viewer  Ctrl+E</i>
     * @see ExternalViewerShortcutAction
     */
    static String ExternalViewerShortcutAction_title_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExternalViewerShortcutAction.title.text");
    }
    /**
     * @return <i>Error extracting unallocated space from image</i>
     * @see ExtractUnallocAction
     */
    static String ExtractUnallocAction_imageError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExtractUnallocAction.imageError");
    }
    /**
     * @return <i>No unallocated files found on volume</i>
     * @see ExtractUnallocAction
     */
    static String ExtractUnallocAction_noFiles() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExtractUnallocAction.noFiles");
    }
    /**
     * @return <i>No open case available.</i>
     * @see ExtractUnallocAction
     */
    static String ExtractUnallocAction_noOpenCase_errMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExtractUnallocAction.noOpenCase.errMsg");
    }
    /**
     * @return <i>Error extracting unallocated space from volume</i>
     * @see ExtractUnallocAction
     */
    static String ExtractUnallocAction_volumeError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExtractUnallocAction.volumeError");
    }
    /**
     * @param fileName fileName
     * @return <i>Already extracting unallocated space into </i>{@code fileName}<i> - will skip this volume</i>
     * @see ExtractUnallocAction
     */
    static String ExtractUnallocAction_volumeInProgress(Object fileName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExtractUnallocAction.volumeInProgress", fileName);
    }
    /**
     * @return <i>File System Details</i>
     * @see FileSystemDetailsAction
     */
    static String FileSystemDetailsAction_title_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSystemDetailsAction.title.text");
    }
    /**
     * @param dataSourceCount dataSourceCount
     * @return <i>This case contains </i>{@code dataSourceCount}<i> data sources.</i>
     * @see GroupDataSourcesDialog
     */
    static String GroupDataSourcesDialog_groupDataSources_text(Object dataSourceCount) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GroupDataSourcesDialog.groupDataSources.text", dataSourceCount);
    }
    /**
     * @return <i>Data Source Files</i>
     * @see SelectionContext
     */
    static String SelectionContext_dataSourceFiles() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SelectionContext.dataSourceFiles");
    }
    /**
     * @return <i>Data Sources</i>
     * @see SelectionContext
     */
    static String SelectionContext_dataSources() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SelectionContext.dataSources");
    }
    /**
     * @return <i>Views</i>
     * @see SelectionContext
     */
    static String SelectionContext_views() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SelectionContext.views");
    }
    /**
     * @return <i>Failed to locate directory.</i>
     * @see ViewContextAction
     */
    static String ViewContextAction_errorMessage_cannotFindDirectory() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewContextAction.errorMessage.cannotFindDirectory");
    }
    /**
     * @return <i>Failed to locate data source node in tree.</i>
     * @see ViewContextAction
     */
    static String ViewContextAction_errorMessage_cannotFindNode() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewContextAction.errorMessage.cannotFindNode");
    }
    /**
     * @return <i>Failed to select directory in tree.</i>
     * @see ViewContextAction
     */
    static String ViewContextAction_errorMessage_cannotSelectDirectory() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewContextAction.errorMessage.cannotSelectDirectory");
    }
    /**
     * @return <i>Unable to navigate to content not supported in this release.</i>
     * @see ViewContextAction
     */
    static String ViewContextAction_errorMessage_unsupportedParent() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ViewContextAction.errorMessage.unsupportedParent");
    }
    private Bundle() {}
}
