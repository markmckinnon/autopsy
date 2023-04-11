package org.sleuthkit.autopsy.discovery.ui;
/** Localizable strings for {@link org.sleuthkit.autopsy.discovery.ui}. */
class Bundle {
    /**
     * @return <i>Open in external viewer</i>
     * @see ArtifactMenuMouseAdapter
     */
    static String ArtifactMenuMouseAdapter_ExternalViewer_label() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ArtifactMenuMouseAdapter_ExternalViewer_label");
    }
    /**
     * @return <i>Extract Files</i>
     * @see ArtifactMenuMouseAdapter
     */
    static String ArtifactMenuMouseAdapter_label() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ArtifactMenuMouseAdapter_label");
    }
    /**
     * @return <i>File does not exist.</i>
     * @see ArtifactMenuMouseAdapter
     */
    static String ArtifactMenuMouseAdapter_noFile_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ArtifactMenuMouseAdapter.noFile.text");
    }
    /**
     * @return <i>At least one Result type must be selected.</i>
     * @see ArtifactTypeFilterPanel
     */
    static String ArtifactTypeFilterPanel_selectionNeeded_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ArtifactTypeFilterPanel.selectionNeeded.text");
    }
    /**
     * @return <i>Date/Time</i>
     * @see ArtifactsListPanel
     */
    static String ArtifactsListPanel_dateColumn_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ArtifactsListPanel.dateColumn.name");
    }
    /**
     * @return <i>Name</i>
     * @see ArtifactsListPanel
     */
    static String ArtifactsListPanel_fileNameColumn_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ArtifactsListPanel.fileNameColumn.name");
    }
    /**
     * @return <i>MIME Type</i>
     * @see ArtifactsListPanel
     */
    static String ArtifactsListPanel_mimeTypeColumn_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ArtifactsListPanel.mimeTypeColumn.name");
    }
    /**
     * @return <i>No results found</i>
     * @see ArtifactsListPanel
     */
    static String ArtifactsListPanel_noResultsFound_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ArtifactsListPanel.noResultsFound.text");
    }
    /**
     * @return <i>Term</i>
     * @see ArtifactsListPanel
     */
    static String ArtifactsListPanel_termColumn_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ArtifactsListPanel.termColumn.name");
    }
    /**
     * @return <i>Title</i>
     * @see ArtifactsListPanel
     */
    static String ArtifactsListPanel_titleColumn_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ArtifactsListPanel.titleColumn.name");
    }
    /**
     * @return <i>URL</i>
     * @see ArtifactsListPanel
     */
    static String ArtifactsListPanel_urlColumn_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ArtifactsListPanel.urlColumn.name");
    }
    /**
     * @return <i>No value available.</i>
     * @see ArtifactsListPanel
     */
    static String ArtifactsListPanel_value_noValue() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ArtifactsListPanel.value.noValue");
    }
    /**
     * @return <i>Discovery</i>
     * @see OpenDiscoveryAction
     */
    static String CTL_OpenDiscoveryAction() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CTL_OpenDiscoveryAction");
    }
    /**
     * @return <i>At least one data source must be selected.</i>
     * @see DataSourceFilterPanel
     */
    static String DataSourceFilterPanel_error_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceFilterPanel.error.text");
    }
    /**
     * @param dataSourceName dataSourceName
     * @return <i>Picture Analyzer module was not run on data source: </i>{@code dataSourceName}<i><br></i>
     * @see DataSourceModulesWrapper
     */
    static String DataSourceModuleWrapper_exifModule_text(Object dataSourceName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceModuleWrapper.exifModule.text", dataSourceName);
    }
    /**
     * @param dataSourceName dataSourceName
     * @return <i>File Type Identification module was not run on data source: </i>{@code dataSourceName}<i><br></i>
     * @see DataSourceModulesWrapper
     */
    static String DataSourceModuleWrapper_fileTypeModule_text(Object dataSourceName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceModuleWrapper.fileTypeModule.text", dataSourceName);
    }
    /**
     * @param dataSourceName dataSourceName
     * @return <i>Hash Lookup module was not run on data source: </i>{@code dataSourceName}<i><br></i>
     * @see DataSourceModulesWrapper
     */
    static String DataSourceModuleWrapper_hashModule_text(Object dataSourceName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceModuleWrapper.hashModule.text", dataSourceName);
    }
    /**
     * @param timeZone timeZone
     * @return <i>Date Range (</i>{@code timeZone}<i>):</i>
     * @see DateFilterPanel
     */
    static String DateFilterPanel_dateRange_text(Object timeZone) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DateFilterPanel.dateRange.text", timeZone);
    }
    /**
     * @return <i>Range or Only Last must be selected.</i>
     * @see DateFilterPanel
     */
    static String DateFilterPanel_invalidRange_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DateFilterPanel.invalidRange.text");
    }
    /**
     * @return <i>Start date should be before the end date when both are enabled.</i>
     * @see DateFilterPanel
     */
    static String DateFilterPanel_startAfterEnd_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DateFilterPanel.startAfterEnd.text");
    }
    /**
     * @return <i>A start or end date must be specified to use the range filter.</i>
     * @see DateFilterPanel
     */
    static String DateFilterPanel_startOrEndNeeded_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DateFilterPanel.startOrEndNeeded.text");
    }
    /**
     * @return <i>Discovery</i>
     * @see DiscoveryDialog
     */
    static String DiscoveryDialog_name_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryDialog.name.text");
    }
    /**
     * @return <i>Extract File</i>
     * @see DiscoveryExtractAction
     */
    static String DiscoveryExtractAction_title_extractFiles_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryExtractAction.title.extractFiles.text");
    }
    /**
     * @return <i>; </i>
     * @see DiscoveryTopComponent
     */
    static String DiscoveryTopComponent_additionalFilters_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryTopComponent.additionalFilters.text");
    }
    /**
     * @return <i>Cancel Search</i>
     * @see DiscoveryTopComponent
     */
    static String DiscoveryTopComponent_cancelButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryTopComponent.cancelButton.text");
    }
    /**
     * @return <i>Type: Domain</i>
     * @see DiscoveryTopComponent
     */
    static String DiscoveryTopComponent_domainSearch_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryTopComponent.domainSearch.text");
    }
    /**
     * @return <i> Discovery</i>
     * @see DiscoveryTopComponent
     */
    static String DiscoveryTopComponent_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryTopComponent.name");
    }
    /**
     * @return <i>New Search</i>
     * @see DiscoveryTopComponent
     */
    static String DiscoveryTopComponent_newSearch_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryTopComponent.newSearch.text");
    }
    /**
     * @return <i>Search has been cancelled.</i>
     * @see DiscoveryTopComponent
     */
    static String DiscoveryTopComponent_searchCancelled_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryTopComponent.searchCancelled.text");
    }
    /**
     * @param search search
     * @return <i>Results with </i>{@code search}
     * @see DiscoveryTopComponent
     */
    static String DiscoveryTopComponent_searchComplete_text(Object search) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryTopComponent.searchComplete.text", search);
    }
    /**
     * @return <i>Error no type specified for search.</i>
     * @see DiscoveryTopComponent
     */
    static String DiscoveryTopComponent_searchError_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryTopComponent.searchError.text");
    }
    /**
     * @param searchType searchType
     * @return <i>Performing search for results of type </i>{@code searchType}<i>. Please wait.</i>
     * @see DiscoveryTopComponent
     */
    static String DiscoveryTopComponent_searchInProgress_text(Object searchType) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryTopComponent.searchInProgress.text", searchType);
    }
    /**
     * @return <i>bytes</i>
     * @see DiscoveryUiUtils
     */
    static String DiscoveryUiUtility_bytes_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryUiUtility.bytes.text");
    }
    /**
     * @return <i>GB</i>
     * @see DiscoveryUiUtils
     */
    static String DiscoveryUiUtility_gigaBytes_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryUiUtility.gigaBytes.text");
    }
    /**
     * @return <i>KB</i>
     * @see DiscoveryUiUtils
     */
    static String DiscoveryUiUtility_kiloBytes_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryUiUtility.kiloBytes.text");
    }
    /**
     * @return <i>MB</i>
     * @see DiscoveryUiUtils
     */
    static String DiscoveryUiUtility_megaBytes_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryUiUtility.megaBytes.text");
    }
    /**
     * @param fileSize fileSize
     * @param units units
     * @return <i>Size: </i>{@code fileSize}<i> </i>{@code units}
     * @see DiscoveryUiUtils
     */
    static String DiscoveryUiUtility_sizeLabel_text(Object fileSize, Object units) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryUiUtility.sizeLabel.text", fileSize, units);
    }
    /**
     * @return <i>TB</i>
     * @see DiscoveryUiUtils
     */
    static String DiscoveryUiUtility_terraBytes_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryUiUtility.terraBytes.text");
    }
    /**
     * @param file_name file name
     * @return <i>extracting temporary file </i>{@code file_name}
     * @see DiscoveryUiUtils
     */
    static String DiscoveryUiUtils_genVideoThumb_progress_text(Object file_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryUiUtils.genVideoThumb.progress.text", file_name);
    }
    /**
     * @return <i>All instances of file are deleted.</i>
     * @see DiscoveryUiUtils
     */
    static String DiscoveryUiUtils_isDeleted_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryUiUtils.isDeleted.text");
    }
    /**
     * @return <i>Discovery results may be incomplete</i>
     * @see DiscoveryUiUtils
     */
    static String DiscoveryUiUtils_resultsIncomplete_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryUiUtils.resultsIncomplete.text");
    }
    /**
     * @param otherInstanceCount otherInstanceCount
     * @return <i> and </i>{@code otherInstanceCount}<i> more</i>
     * @see DocumentPanel
     */
    static String DocumentPanel_nameLabel_more_text(Object otherInstanceCount) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DocumentPanel.nameLabel.more.text", otherInstanceCount);
    }
    /**
     * @return <i>0 of ? images</i>
     * @see DocumentPanel
     */
    static String DocumentPanel_noImageExtraction_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DocumentPanel.noImageExtraction.text");
    }
    /**
     * @return <i>No images</i>
     * @see DocumentPanel
     */
    static String DocumentPanel_numberOfImages_noImages() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DocumentPanel.numberOfImages.noImages");
    }
    /**
     * @param numberOfImages numberOfImages
     * @return <i>1 of </i>{@code numberOfImages}<i> images</i>
     * @see DocumentPanel
     */
    static String DocumentPanel_numberOfImages_text(Object numberOfImages) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DocumentPanel.numberOfImages.text", numberOfImages);
    }
    /**
     * @return <i>Preview not generated yet.</i>
     * @see DocumentWrapper
     */
    static String DocumentWrapper_previewInitialValue() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DocumentWrapper.previewInitialValue");
    }
    /**
     * @return <i>Timeline</i>
     * @see DomainDetailsPanel
     */
    static String DomainDetailsPanel_miniTimelineTitle_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DomainDetailsPanel.miniTimelineTitle.text");
    }
    /**
     * @return <i>Other Occurrences</i>
     * @see DomainDetailsPanel
     */
    static String DomainDetailsPanel_otherOccurrencesTab_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DomainDetailsPanel.otherOccurrencesTab.title");
    }
    /**
     * @param startDate startDate
     * @param endDate endDate
     * @return <i>Activity: </i>{@code startDate}<i> to </i>{@code endDate}
     * @see DomainSummaryPanel
     */
    static String DomainSummaryPanel_activity_text(Object startDate, Object endDate) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DomainSummaryPanel.activity.text", startDate, endDate);
    }
    /**
     * @return <i>Categories: </i>
     * @see DomainSummaryPanel
     */
    static String DomainSummaryPanel_category_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DomainSummaryPanel.category.text");
    }
    /**
     * @return <i>Files downloaded: </i>
     * @see DomainSummaryPanel
     */
    static String DomainSummaryPanel_downloads_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DomainSummaryPanel.downloads.text");
    }
    /**
     * @return <i>Loading thumbnail...</i>
     * @see DomainSummaryPanel
     */
    static String DomainSummaryPanel_loadingImages_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DomainSummaryPanel.loadingImages.text");
    }
    /**
     * @return <i>No</i>
     * @see DomainSummaryPanel
     */
    static String DomainSummaryPanel_no_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DomainSummaryPanel.no.text");
    }
    /**
     * @return <i>Previously tagged as notable: </i>
     * @see DomainSummaryPanel
     */
    static String DomainSummaryPanel_notability_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DomainSummaryPanel.notability.text");
    }
    /**
     * @return <i>Page views in final 60 days: </i>
     * @see DomainSummaryPanel
     */
    static String DomainSummaryPanel_pages_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DomainSummaryPanel.pages.text");
    }
    /**
     * @return <i>Total page views: </i>
     * @see DomainSummaryPanel
     */
    static String DomainSummaryPanel_totalPages_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DomainSummaryPanel.totalPages.text");
    }
    /**
     * @return <i>Account type: </i>
     * @see DomainSummaryPanel
     */
    static String DomainSummaryPanel_userRole_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DomainSummaryPanel.userRole.text");
    }
    /**
     * @return <i>Yes</i>
     * @see DomainSummaryPanel
     */
    static String DomainSummaryPanel_yes_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DomainSummaryPanel.yes.text");
    }
    /**
     * @return <i>No domains were found for the selected filters.<br><br>Reminder:<br>  -The Recent Activity module must be run on each data source you want to find results in.<br>  -The Central Repository module must be run on each data source if you want to filter or sort by past occurrences.<br>  -The iOS Analyzer (iLEAPP) module must be run on each data source which contains data from an iOS device.<br></i>
     * @see GroupListPanel
     */
    static String GroupsListPanel_noDomainResults_message_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GroupsListPanel.noDomainResults.message.text");
    }
    /**
     * @return <i>No files were found for the selected filters.<br><br>Reminder:<br>  -The File Type Identification module must be run on each data source you want to find results in.<br>  -The Hash Lookup module must be run on each data source if you want to filter by past occurrence.<br>  -The Picture Analyzer module must be run on each data source if you are filtering by User Created content.</i>
     * @see GroupListPanel
     */
    static String GroupsListPanel_noFileResults_message_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GroupsListPanel.noFileResults.message.text");
    }
    /**
     * @return <i>No results found</i>
     * @see GroupListPanel
     */
    static String GroupsListPanel_noResults_title_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GroupsListPanel.noResults.title.text");
    }
    /**
     * @return <i>At least one hash set name must be selected.</i>
     * @see HashSetFilterPanel
     */
    static String HashSetFilterPanel_error_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashSetFilterPanel.error.text");
    }
    /**
     * @return <i>All instances of file are deleted.</i>
     * @see ImageThumbnailPanel
     */
    static String ImageThumbnailPanel_isDeleted_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ImageThumbnailPanel.isDeleted.text");
    }
    /**
     * @param otherInstanceCount otherInstanceCount
     * @return <i> and </i>{@code otherInstanceCount}<i> more</i>
     * @see ImageThumbnailPanel
     */
    static String ImageThumbnailPanel_nameLabel_more_text(Object otherInstanceCount) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ImageThumbnailPanel.nameLabel.more.text", otherInstanceCount);
    }
    /**
     * @return <i>At least one interesting file set name must be selected.</i>
     * @see InterestingItemsFilterPanel
     */
    static String InterestingItemsFilterPanel_error_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "InterestingItemsFilterPanel.error.text");
    }
    /**
     * @return <i>Loading, please wait.</i>
     * @see LoadingPanel
     */
    static String LoadingPanel_loading_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LoadingPanel.loading.text");
    }
    /**
     * @param resultInfo resultInfo
     * @return <i>Retrieving results for </i>{@code resultInfo}<i>.</i>
     * @see LoadingPanel
     */
    static String LoadingPanel_retrieving_text(Object resultInfo) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LoadingPanel.retrieving.text", resultInfo);
    }
    /**
     * @return <i> Description</i>
     * @see MiniTimelineArtifactListPanel
     */
    static String MiniTimelineArtifactListPanel_descriptionColumn_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MiniTimelineArtifactListPanel.descriptionColumn.name");
    }
    /**
     * @return <i>Result Type</i>
     * @see MiniTimelineArtifactListPanel
     */
    static String MiniTimelineArtifactListPanel_typeColumn_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MiniTimelineArtifactListPanel.typeColumn.name");
    }
    /**
     * @return <i>No value available.</i>
     * @see MiniTimelineArtifactListPanel
     */
    static String MiniTimelineArtifactListPanel_value_noValue() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MiniTimelineArtifactListPanel.value.noValue");
    }
    /**
     * @return <i>Count</i>
     * @see MiniTimelineDateListPanel
     */
    static String MiniTimelineDateListPanel_countColumn_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MiniTimelineDateListPanel.countColumn.name");
    }
    /**
     * @return <i>Date</i>
     * @see MiniTimelineDateListPanel
     */
    static String MiniTimelineDateListPanel_dateColumn_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MiniTimelineDateListPanel.dateColumn.name");
    }
    /**
     * @return <i>No value available.</i>
     * @see MiniTimelineDateListPanel
     */
    static String MiniTimelineDateListPanel_value_noValue() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MiniTimelineDateListPanel.value.noValue");
    }
    /**
     * @return <i>the Timeline view</i>
     * @see MiniTimelinePanel
     */
    static String MiniTimelinePanel_loadingPanel_details() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MiniTimelinePanel.loadingPanel.details");
    }
    /**
     * @return <i>Apr</i>
     * @see MonthAbbreviation
     */
    static String MonthAbbreviation_aprilAbbrev() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MonthAbbreviation.aprilAbbrev");
    }
    /**
     * @return <i>Aug</i>
     * @see MonthAbbreviation
     */
    static String MonthAbbreviation_augustAbbrev() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MonthAbbreviation.augustAbbrev");
    }
    /**
     * @return <i>Dec</i>
     * @see MonthAbbreviation
     */
    static String MonthAbbreviation_decemberAbbrev() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MonthAbbreviation.decemberAbbrev");
    }
    /**
     * @return <i>Feb</i>
     * @see MonthAbbreviation
     */
    static String MonthAbbreviation_feburaryAbbrev() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MonthAbbreviation.feburaryAbbrev");
    }
    /**
     * @return <i>Jan</i>
     * @see MonthAbbreviation
     */
    static String MonthAbbreviation_januraryAbbrev() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MonthAbbreviation.januraryAbbrev");
    }
    /**
     * @return <i>Jul</i>
     * @see MonthAbbreviation
     */
    static String MonthAbbreviation_julyAbbrev() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MonthAbbreviation.julyAbbrev");
    }
    /**
     * @return <i>Jun</i>
     * @see MonthAbbreviation
     */
    static String MonthAbbreviation_juneAbbrev() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MonthAbbreviation.juneAbbrev");
    }
    /**
     * @return <i>Mar</i>
     * @see MonthAbbreviation
     */
    static String MonthAbbreviation_marchAbbrev() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MonthAbbreviation.marchAbbrev");
    }
    /**
     * @return <i>May</i>
     * @see MonthAbbreviation
     */
    static String MonthAbbreviation_mayAbbrev() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MonthAbbreviation.mayAbbrev");
    }
    /**
     * @return <i>Nov</i>
     * @see MonthAbbreviation
     */
    static String MonthAbbreviation_novemberAbbrev() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MonthAbbreviation.novemberAbbrev");
    }
    /**
     * @return <i>Oct</i>
     * @see MonthAbbreviation
     */
    static String MonthAbbreviation_octoberAbbrev() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MonthAbbreviation.octoberAbbrev");
    }
    /**
     * @return <i>Sep</i>
     * @see MonthAbbreviation
     */
    static String MonthAbbreviation_septemberAbbrev() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MonthAbbreviation.septemberAbbrev");
    }
    /**
     * @return <i>At least one object type name must be selected.</i>
     * @see ObjectDetectedFilterPanel
     */
    static String ObjectDetectedFilterPanel_error_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ObjectDetectedFilterPanel.error.text");
    }
    /**
     * @return <i>At least one parent path must be entered.</i>
     * @see ParentFolderFilterPanel
     */
    static String ParentFolderFilterPanel_error_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ParentFolderFilterPanel.error.text");
    }
    /**
     * @return <i>At least one value in the past occurrence filter must be selected.</i>
     * @see PastOccurrencesFilterPanel
     */
    static String PastOccurrencesFilterPanel_error_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PastOccurrencesFilterPanel.error.text");
    }
    /**
     * @param currentPage currentPage
     * @param totalPages totalPages
     * @return <i>Page: </i>{@code currentPage}<i> of </i>{@code totalPages}
     * @see ResultsPanel
     */
    static String ResultsPanel_currentPage_displayValue(Object currentPage, Object totalPages) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ResultsPanel.currentPage.displayValue", currentPage, totalPages);
    }
    /**
     * @return <i>Document preview creation cancelled.</i>
     * @see ResultsPanel
     */
    static String ResultsPanel_documentPreview_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ResultsPanel.documentPreview.text");
    }
    /**
     * @param selectedPage selectedPage
     * @param maxPage maxPage
     * @return <i>The selected page number </i>{@code selectedPage}<i> does not exist. Please select a value from 1 to </i>{@code maxPage}<i>.</i>
     * @see ResultsPanel
     */
    static String ResultsPanel_invalidPageNumber_message(Object selectedPage, Object maxPage) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ResultsPanel.invalidPageNumber.message", selectedPage, maxPage);
    }
    /**
     * @return <i>Invalid Page Number</i>
     * @see ResultsPanel
     */
    static String ResultsPanel_invalidPageNumber_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ResultsPanel.invalidPageNumber.title");
    }
    /**
     * @return <i>Open in External Viewer</i>
     * @see ResultsPanel
     */
    static String ResultsPanel_openInExternalViewer_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ResultsPanel.openInExternalViewer.name");
    }
    /**
     * @return <i>Unable to create summary.</i>
     * @see ResultsPanel
     */
    static String ResultsPanel_unableToCreate_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ResultsPanel.unableToCreate.text");
    }
    /**
     * @return <i>View File in Directory</i>
     * @see ResultsPanel
     */
    static String ResultsPanel_viewFileInDir_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ResultsPanel.viewFileInDir.name");
    }
    /**
     * @return <i>At least one size must be selected.</i>
     * @see SizeFilterPanel
     */
    static String SizeFilterPanel_error_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SizeFilterPanel.error.text");
    }
    /**
     * @return <i>bytes</i>
     * @see VideoThumbnailPanel
     */
    static String VideoThumbnailPanel_bytes_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VideoThumbnailPanel.bytes.text");
    }
    /**
     * @return <i>All instances of file are deleted.</i>
     * @see VideoThumbnailPanel
     */
    static String VideoThumbnailPanel_deleted_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VideoThumbnailPanel.deleted.text");
    }
    /**
     * @return <i>GB</i>
     * @see VideoThumbnailPanel
     */
    static String VideoThumbnailPanel_gigaBytes_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VideoThumbnailPanel.gigaBytes.text");
    }
    /**
     * @return <i>KB</i>
     * @see VideoThumbnailPanel
     */
    static String VideoThumbnailPanel_kiloBytes_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VideoThumbnailPanel.kiloBytes.text");
    }
    /**
     * @return <i>MB</i>
     * @see VideoThumbnailPanel
     */
    static String VideoThumbnailPanel_megaBytes_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VideoThumbnailPanel.megaBytes.text");
    }
    /**
     * @param otherInstanceCount otherInstanceCount
     * @return <i> and </i>{@code otherInstanceCount}<i> more</i>
     * @see VideoThumbnailPanel
     */
    static String VideoThumbnailPanel_nameLabel_more_text(Object otherInstanceCount) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VideoThumbnailPanel.nameLabel.more.text", otherInstanceCount);
    }
    /**
     * @param fileSize fileSize
     * @param units units
     * @return <i>Size: </i>{@code fileSize}<i> </i>{@code units}
     * @see VideoThumbnailPanel
     */
    static String VideoThumbnailPanel_sizeLabel_text(Object fileSize, Object units) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VideoThumbnailPanel.sizeLabel.text", fileSize, units);
    }
    /**
     * @return <i>TB</i>
     * @see VideoThumbnailPanel
     */
    static String VideoThumbnailPanel_terraBytes_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VideoThumbnailPanel.terraBytes.text");
    }
    private Bundle() {}
}
