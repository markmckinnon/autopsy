package org.sleuthkit.autopsy.report.modules.datasourcesummaryexport;
/** Localizable strings for {@link org.sleuthkit.autopsy.report.modules.datasourcesummaryexport}. */
class Bundle {
    /**
     * @return <i>No data sources selected for report.</i>
     * @see DataSourceSummaryReport
     */
    static String DataSourceSummaryReport_error_noDataSources() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceSummaryReport.error.noDataSources");
    }
    /**
     * @return <i>No currently open case.</i>
     * @see DataSourceSummaryReport
     */
    static String DataSourceSummaryReport_error_noOpenCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceSummaryReport.error.noOpenCase");
    }
    /**
     * @return <i>Could not write the xlsx file.</i>
     * @see DataSourceSummaryReport
     */
    static String DataSourceSummaryReport_excelFileWriteError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceSummaryReport.excelFileWriteError");
    }
    /**
     * @return <i>Failed to complete report.</i>
     * @see DataSourceSummaryReport
     */
    static String DataSourceSummaryReport_failedToCompleteReport() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceSummaryReport.failedToCompleteReport");
    }
    /**
     * @return <i>Beginning Export...</i>
     * @see ExcelExportAction
     */
    static String ExcelExportAction_exportToXLSX_beginExport() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExcelExportAction_exportToXLSX_beginExport");
    }
    /**
     * @return <i>Fetching Analysis Data</i>
     * @see ExcelExportAction
     */
    static String ExcelExportAction_exportToXLSX_gatheringAnalysisData() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExcelExportAction_exportToXLSX_gatheringAnalysisData");
    }
    /**
     * @return <i>Fetching Container &amp; Image Data</i>
     * @see ExcelExportAction
     */
    static String ExcelExportAction_exportToXLSX_gatheringContainerData() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExcelExportAction_exportToXLSX_gatheringContainerData");
    }
    /**
     * @return <i>Fetching File and MIME Type Data</i>
     * @see ExcelExportAction
     */
    static String ExcelExportAction_exportToXLSX_gatheringFileData() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExcelExportAction_exportToXLSX_gatheringFileData");
    }
    /**
     * @return <i>Fetching Geolocation Data</i>
     * @see ExcelExportAction
     */
    static String ExcelExportAction_exportToXLSX_gatheringGeoData() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExcelExportAction_exportToXLSX_gatheringGeoData");
    }
    /**
     * @return <i>Fetching Ingest History Data</i>
     * @see ExcelExportAction
     */
    static String ExcelExportAction_exportToXLSX_gatheringIngestData() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExcelExportAction_exportToXLSX_gatheringIngestData");
    }
    /**
     * @return <i>Fetching Historical Data</i>
     * @see ExcelExportAction
     */
    static String ExcelExportAction_exportToXLSX_gatheringPastData() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExcelExportAction_exportToXLSX_gatheringPastData");
    }
    /**
     * @return <i>Fetching Recent Activity Data</i>
     * @see ExcelExportAction
     */
    static String ExcelExportAction_exportToXLSX_gatheringRecentActivityData() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExcelExportAction_exportToXLSX_gatheringRecentActivityData");
    }
    /**
     * @return <i>Fetching Timeline Data</i>
     * @see ExcelExportAction
     */
    static String ExcelExportAction_exportToXLSX_gatheringTimelineData() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExcelExportAction_exportToXLSX_gatheringTimelineData");
    }
    /**
     * @return <i>Fetching User Activity Data</i>
     * @see ExcelExportAction
     */
    static String ExcelExportAction_exportToXLSX_gatheringUserData() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExcelExportAction_exportToXLSX_gatheringUserData");
    }
    /**
     * @return <i>Writing to File...</i>
     * @see ExcelExportAction
     */
    static String ExcelExportAction_exportToXLSX_writingToFile() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExcelExportAction_exportToXLSX_writingToFile");
    }
    /**
     * @return <i>DataSourceSummary</i>
     * @see ExcelExportAction
     */
    static String ExcelExportAction_getXLSXPath_directory() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExcelExportAction_getXLSXPath_directory");
    }
    /**
     * @return <i>Data Source Summary</i>
     * @see ExcelExportAction
     */
    static String ExcelExportAction_moduleName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExcelExportAction_moduleName");
    }
    /**
     * @param sheetNumber sheetNumber
     * @return <i>Sheet </i>{@code sheetNumber}
     * @see ExcelExport
     */
    static String ExcelExport_writeExcel_noSheetName(Object sheetNumber) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExcelExport_writeExcel_noSheetName", sheetNumber);
    }
    /**
     * @return <i>Count</i>
     * @see ExportAnalysisResults
     */
    static String ExportAnalysisResults_countColumn_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportAnalysisResults_countColumn_title");
    }
    /**
     * @return <i>Hashset Hits</i>
     * @see ExportAnalysisResults
     */
    static String ExportAnalysisResults_hashsetHits_tabName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportAnalysisResults_hashsetHits_tabName");
    }
    /**
     * @return <i>Interesting Item Hits</i>
     * @see ExportAnalysisResults
     */
    static String ExportAnalysisResults_interestingItemHits_tabName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportAnalysisResults_interestingItemHits_tabName");
    }
    /**
     * @return <i>Name</i>
     * @see ExportAnalysisResults
     */
    static String ExportAnalysisResults_keyColumn_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportAnalysisResults_keyColumn_title");
    }
    /**
     * @return <i>Keyword Hits</i>
     * @see ExportAnalysisResults
     */
    static String ExportAnalysisResults_keywordHits_tabName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportAnalysisResults_keywordHits_tabName");
    }
    /**
     * @return <i>Keyword Search</i>
     * @see ExportAnalysisResults
     */
    static String ExportAnalysisResults_keywordSearchModuleName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportAnalysisResults_keywordSearchModuleName");
    }
    /**
     * @return <i>Acquisition Details:</i>
     * @see ExportContainerInfo
     */
    static String ExportContainerInfo_export_acquisitionDetails() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportContainerInfo_export_acquisitionDetails");
    }
    /**
     * @return <i>Device ID:</i>
     * @see ExportContainerInfo
     */
    static String ExportContainerInfo_export_deviceId() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportContainerInfo_export_deviceId");
    }
    /**
     * @return <i>Display Name:</i>
     * @see ExportContainerInfo
     */
    static String ExportContainerInfo_export_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportContainerInfo_export_displayName");
    }
    /**
     * @return <i>File Paths:</i>
     * @see ExportContainerInfo
     */
    static String ExportContainerInfo_export_filePaths() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportContainerInfo_export_filePaths");
    }
    /**
     * @return <i>Image Type:</i>
     * @see ExportContainerInfo
     */
    static String ExportContainerInfo_export_imageType() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportContainerInfo_export_imageType");
    }
    /**
     * @return <i>MD5:</i>
     * @see ExportContainerInfo
     */
    static String ExportContainerInfo_export_md5() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportContainerInfo_export_md5");
    }
    /**
     * @return <i>Name:</i>
     * @see ExportContainerInfo
     */
    static String ExportContainerInfo_export_originalName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportContainerInfo_export_originalName");
    }
    /**
     * @return <i>Sector Size:</i>
     * @see ExportContainerInfo
     */
    static String ExportContainerInfo_export_sectorSize() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportContainerInfo_export_sectorSize");
    }
    /**
     * @return <i>SHA1:</i>
     * @see ExportContainerInfo
     */
    static String ExportContainerInfo_export_sha1() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportContainerInfo_export_sha1");
    }
    /**
     * @return <i>SHA256:</i>
     * @see ExportContainerInfo
     */
    static String ExportContainerInfo_export_sha256() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportContainerInfo_export_sha256");
    }
    /**
     * @return <i>Size:</i>
     * @see ExportContainerInfo
     */
    static String ExportContainerInfo_export_size() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportContainerInfo_export_size");
    }
    /**
     * @return <i>Time Zone:</i>
     * @see ExportContainerInfo
     */
    static String ExportContainerInfo_export_timeZone() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportContainerInfo_export_timeZone");
    }
    /**
     * @return <i>Unallocated Space:</i>
     * @see ExportContainerInfo
     */
    static String ExportContainerInfo_export_unallocatedSize() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportContainerInfo_export_unallocatedSize");
    }
    /**
     * @return <i>N/A</i>
     * @see ExportContainerInfo
     */
    static String ExportContainerInfo_setFieldsForNonImageDataSource_na() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportContainerInfo_setFieldsForNonImageDataSource_na");
    }
    /**
     * @return <i>Container</i>
     * @see ExportContainerInfo
     */
    static String ExportContainerInfo_tabName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportContainerInfo_tabName");
    }
    /**
     * @return <i>Closest City</i>
     * @see ExportGeolocation
     */
    static String ExportGeolocation_cityColumn_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportGeolocation_cityColumn_title");
    }
    /**
     * @return <i>Count</i>
     * @see ExportGeolocation
     */
    static String ExportGeolocation_countColumn_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportGeolocation_countColumn_title");
    }
    /**
     * @return <i>Most Common Cities</i>
     * @see ExportGeolocation
     */
    static String ExportGeolocation_mostCommon_tabName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportGeolocation_mostCommon_tabName");
    }
    /**
     * @return <i>Most Recent Cities</i>
     * @see ExportGeolocation
     */
    static String ExportGeolocation_mostRecent_tabName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportGeolocation_mostRecent_tabName");
    }
    /**
     * @return <i>Unknown</i>
     * @see ExportGeolocation
     */
    static String ExportGeolocation_unknownRow_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportGeolocation_unknownRow_title");
    }
    /**
     * @return <i>End Time</i>
     * @see ExportIngestHistory
     */
    static String ExportIngestHistory_endTimeColumn() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportIngestHistory_endTimeColumn");
    }
    /**
     * @return <i>Ingest Status</i>
     * @see ExportIngestHistory
     */
    static String ExportIngestHistory_ingestStatusTimeColumn() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportIngestHistory_ingestStatusTimeColumn");
    }
    /**
     * @return <i>Module Name</i>
     * @see ExportIngestHistory
     */
    static String ExportIngestHistory_moduleNameTimeColumn() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportIngestHistory_moduleNameTimeColumn");
    }
    /**
     * @return <i>Ingest History</i>
     * @see ExportIngestHistory
     */
    static String ExportIngestHistory_sheetName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportIngestHistory_sheetName");
    }
    /**
     * @return <i>Start Time</i>
     * @see ExportIngestHistory
     */
    static String ExportIngestHistory_startTimeColumn() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportIngestHistory_startTimeColumn");
    }
    /**
     * @return <i>Module Version</i>
     * @see ExportIngestHistory
     */
    static String ExportIngestHistory_versionColumn() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportIngestHistory_versionColumn");
    }
    /**
     * @return <i>Case</i>
     * @see ExportPastCases
     */
    static String ExportPastCases_caseColumn_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportPastCases_caseColumn_title");
    }
    /**
     * @return <i>Count</i>
     * @see ExportPastCases
     */
    static String ExportPastCases_countColumn_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportPastCases_countColumn_title");
    }
    /**
     * @return <i>Cases with common notable items</i>
     * @see ExportPastCases
     */
    static String ExportPastCases_notableFileTable_tabName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportPastCases_notableFileTable_tabName");
    }
    /**
     * @return <i>Cases with the same device IDs</i>
     * @see ExportPastCases
     */
    static String ExportPastCases_seenDevicesTable_tabName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportPastCases_seenDevicesTable_tabName");
    }
    /**
     * @return <i>Cases with the same addresses</i>
     * @see ExportPastCases
     */
    static String ExportPastCases_seenResultsTable_tabName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportPastCases_seenResultsTable_tabName");
    }
    /**
     * @return <i>Recent Attachments</i>
     * @see ExportRecentFiles
     */
    static String ExportRecentFiles_attachmentsTable_tabName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportRecentFiles_attachmentsTable_tabName");
    }
    /**
     * @return <i>Date</i>
     * @see ExportRecentFiles
     */
    static String ExportRecentFiles_col_head_date() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportRecentFiles_col_head_date");
    }
    /**
     * @return <i>Domain</i>
     * @see ExportRecentFiles
     */
    static String ExportRecentFiles_col_header_domain() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportRecentFiles_col_header_domain");
    }
    /**
     * @return <i>Path</i>
     * @see ExportRecentFiles
     */
    static String ExportRecentFiles_col_header_path() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportRecentFiles_col_header_path");
    }
    /**
     * @return <i>Sender</i>
     * @see ExportRecentFiles
     */
    static String ExportRecentFiles_col_header_sender() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportRecentFiles_col_header_sender");
    }
    /**
     * @return <i>Recently Opened Documents</i>
     * @see ExportRecentFiles
     */
    static String ExportRecentFiles_docsTable_tabName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportRecentFiles_docsTable_tabName");
    }
    /**
     * @return <i>Recent Downloads</i>
     * @see ExportRecentFiles
     */
    static String ExportRecentFiles_downloadsTable_tabName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportRecentFiles_downloadsTable_tabName");
    }
    /**
     * @return <i>Artifact Types</i>
     * @see ExportTypes
     */
    static String ExportTypes_artifactsTypesPieChart_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportTypes_artifactsTypesPieChart_title");
    }
    /**
     * @return <i>Types</i>
     * @see ExportTypes
     */
    static String ExportTypes_excelTabName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportTypes_excelTabName");
    }
    /**
     * @return <i>Audio</i>
     * @see ExportTypes
     */
    static String ExportTypes_fileMimeTypesChart_audio_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportTypes_fileMimeTypesChart_audio_title");
    }
    /**
     * @return <i>Documents</i>
     * @see ExportTypes
     */
    static String ExportTypes_fileMimeTypesChart_documents_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportTypes_fileMimeTypesChart_documents_title");
    }
    /**
     * @return <i>Executables</i>
     * @see ExportTypes
     */
    static String ExportTypes_fileMimeTypesChart_executables_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportTypes_fileMimeTypesChart_executables_title");
    }
    /**
     * @return <i>Images</i>
     * @see ExportTypes
     */
    static String ExportTypes_fileMimeTypesChart_images_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportTypes_fileMimeTypesChart_images_title");
    }
    /**
     * @return <i>Not Analyzed</i>
     * @see ExportTypes
     */
    static String ExportTypes_fileMimeTypesChart_notAnalyzed_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportTypes_fileMimeTypesChart_notAnalyzed_title");
    }
    /**
     * @return <i>Other</i>
     * @see ExportTypes
     */
    static String ExportTypes_fileMimeTypesChart_other_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportTypes_fileMimeTypesChart_other_title");
    }
    /**
     * @return <i>File Types</i>
     * @see ExportTypes
     */
    static String ExportTypes_fileMimeTypesChart_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportTypes_fileMimeTypesChart_title");
    }
    /**
     * @return <i>Unknown</i>
     * @see ExportTypes
     */
    static String ExportTypes_fileMimeTypesChart_unknown_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportTypes_fileMimeTypesChart_unknown_title");
    }
    /**
     * @return <i>Count</i>
     * @see ExportTypes
     */
    static String ExportTypes_fileMimeTypesChart_valueLabel() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportTypes_fileMimeTypesChart_valueLabel");
    }
    /**
     * @return <i>Videos</i>
     * @see ExportTypes
     */
    static String ExportTypes_fileMimeTypesChart_videos_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportTypes_fileMimeTypesChart_videos_title");
    }
    /**
     * @return <i>Allocated Files</i>
     * @see ExportTypes
     */
    static String ExportTypes_filesByCategoryTable_allocatedRow_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportTypes_filesByCategoryTable_allocatedRow_title");
    }
    /**
     * @return <i>Directories</i>
     * @see ExportTypes
     */
    static String ExportTypes_filesByCategoryTable_directoryRow_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportTypes_filesByCategoryTable_directoryRow_title");
    }
    /**
     * @return <i>Slack Files</i>
     * @see ExportTypes
     */
    static String ExportTypes_filesByCategoryTable_slackRow_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportTypes_filesByCategoryTable_slackRow_title");
    }
    /**
     * @return <i>Unallocated Files</i>
     * @see ExportTypes
     */
    static String ExportTypes_filesByCategoryTable_unallocatedRow_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportTypes_filesByCategoryTable_unallocatedRow_title");
    }
    /**
     * @return <i>OS</i>
     * @see ExportTypes
     */
    static String ExportTypes_osLabel_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportTypes_osLabel_title");
    }
    /**
     * @return <i>Size</i>
     * @see ExportTypes
     */
    static String ExportTypes_sizeLabel_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportTypes_sizeLabel_title");
    }
    /**
     * @return <i>Usage</i>
     * @see ExportTypes
     */
    static String ExportTypes_usageLabel_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportTypes_usageLabel_title");
    }
    /**
     * @return <i>Account Type</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_TopAccountTableModel_accountType_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_TopAccountTableModel_accountType_header");
    }
    /**
     * @return <i>Last Accessed</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_TopAccountTableModel_lastAccess_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_TopAccountTableModel_lastAccess_header");
    }
    /**
     * @return <i>Recent Account Types Used</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_TopAccountTableModel_tabName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_TopAccountTableModel_tabName");
    }
    /**
     * @return <i>Last Accessed</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_TopDeviceAttachedTableModel_dateAccessed_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_TopDeviceAttachedTableModel_dateAccessed_header");
    }
    /**
     * @return <i>Device Id</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_TopDeviceAttachedTableModel_deviceId_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_TopDeviceAttachedTableModel_deviceId_header");
    }
    /**
     * @return <i>Make and Model</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_TopDeviceAttachedTableModel_makeModel_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_TopDeviceAttachedTableModel_makeModel_header");
    }
    /**
     * @return <i>Recent Devices Attached</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_TopDeviceAttachedTableModel_tabName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_TopDeviceAttachedTableModel_tabName");
    }
    /**
     * @return <i>Visits</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_TopDomainsTableModel_count_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_TopDomainsTableModel_count_header");
    }
    /**
     * @return <i>Domain</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_TopDomainsTableModel_domain_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_TopDomainsTableModel_domain_header");
    }
    /**
     * @return <i>Last Accessed</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_TopDomainsTableModel_lastAccess_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_TopDomainsTableModel_lastAccess_header");
    }
    /**
     * @return <i>Recent Domains</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_TopDomainsTableModel_tabName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_TopDomainsTableModel_tabName");
    }
    /**
     * @return <i>Run Times</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_TopProgramsTableModel_count_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_TopProgramsTableModel_count_header");
    }
    /**
     * @return <i>Folder</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_TopProgramsTableModel_folder_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_TopProgramsTableModel_folder_header");
    }
    /**
     * @return <i>Last Run</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_TopProgramsTableModel_lastrun_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_TopProgramsTableModel_lastrun_header");
    }
    /**
     * @return <i>Program</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_TopProgramsTableModel_name_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_TopProgramsTableModel_name_header");
    }
    /**
     * @return <i>Recent Programs</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_TopProgramsTableModel_tabName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_TopProgramsTableModel_tabName");
    }
    /**
     * @return <i>Date Accessed</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_TopWebSearchTableModel_dateAccessed_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_TopWebSearchTableModel_dateAccessed_header");
    }
    /**
     * @return <i>Search String</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_TopWebSearchTableModel_searchString_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_TopWebSearchTableModel_searchString_header");
    }
    /**
     * @return <i>Recent Web Searches</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_TopWebSearchTableModel_tabName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_TopWebSearchTableModel_tabName");
    }
    /**
     * @return <i>Translated</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_TopWebSearchTableModel_translatedResult_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_TopWebSearchTableModel_translatedResult_header");
    }
    /**
     * @return <i>No communication data exists</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_noDataExists() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_noDataExists");
    }
    /**
     * @return <i>User Activity</i>
     * @see ExportUserActivity
     */
    static String ExportUserActivity_tab_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExportUserActivity_tab_title");
    }
    /**
     * @return <i>bytes</i>
     * @see SizeRepresentationUtil
     */
    static String SizeRepresentationUtil_units_bytes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SizeRepresentationUtil_units_bytes");
    }
    /**
     * @return <i>GB</i>
     * @see SizeRepresentationUtil
     */
    static String SizeRepresentationUtil_units_gigabytes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SizeRepresentationUtil_units_gigabytes");
    }
    /**
     * @return <i>KB</i>
     * @see SizeRepresentationUtil
     */
    static String SizeRepresentationUtil_units_kilobytes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SizeRepresentationUtil_units_kilobytes");
    }
    /**
     * @return <i>MB</i>
     * @see SizeRepresentationUtil
     */
    static String SizeRepresentationUtil_units_megabytes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SizeRepresentationUtil_units_megabytes");
    }
    /**
     * @return <i>PB</i>
     * @see SizeRepresentationUtil
     */
    static String SizeRepresentationUtil_units_petabytes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SizeRepresentationUtil_units_petabytes");
    }
    /**
     * @return <i>TB</i>
     * @see SizeRepresentationUtil
     */
    static String SizeRepresentationUtil_units_terabytes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SizeRepresentationUtil_units_terabytes");
    }
    /**
     * @return <i>Earliest</i>
     * @see ExportTimeline
     */
    static String TimelinePanel_earliestLabel_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimelinePanel_earliestLabel_title");
    }
    /**
     * @return <i>Activity Range</i>
     * @see ExportTimeline
     */
    static String TimelinePanel_getExports_activityRange() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimelinePanel_getExports_activityRange");
    }
    /**
     * @return <i>Last 30 Days</i>
     * @see ExportTimeline
     */
    static String TimelinePanel_getExports_chartName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimelinePanel_getExports_chartName");
    }
    /**
     * @return <i>Date</i>
     * @see ExportTimeline
     */
    static String TimelinePanel_getExports_dateColumnHeader() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimelinePanel_getExports_dateColumnHeader");
    }
    /**
     * @return <i>Earliest:</i>
     * @see ExportTimeline
     */
    static String TimelinePanel_getExports_earliest() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimelinePanel_getExports_earliest");
    }
    /**
     * @return <i>Latest:</i>
     * @see ExportTimeline
     */
    static String TimelinePanel_getExports_latest() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimelinePanel_getExports_latest");
    }
    /**
     * @return <i>Timeline</i>
     * @see ExportTimeline
     */
    static String TimelinePanel_getExports_sheetName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimelinePanel_getExports_sheetName");
    }
    /**
     * @return <i>Latest</i>
     * @see ExportTimeline
     */
    static String TimelinePanel_latestLabel_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimelinePanel_latestLabel_title");
    }
    /**
     * @return <i>Result Events</i>
     * @see ExportTimeline
     */
    static String TimlinePanel_last30DaysChart_artifactEvts_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimlinePanel_last30DaysChart_artifactEvts_title");
    }
    /**
     * @return <i>File Events</i>
     * @see ExportTimeline
     */
    static String TimlinePanel_last30DaysChart_fileEvts_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimlinePanel_last30DaysChart_fileEvts_title");
    }
    /**
     * @return <i>Last 30 Days</i>
     * @see ExportTimeline
     */
    static String TimlinePanel_last30DaysChart_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TimlinePanel_last30DaysChart_title");
    }
    private Bundle() {}
}
