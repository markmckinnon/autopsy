package org.sleuthkit.autopsy.discovery.search;
/** Localizable strings for {@link org.sleuthkit.autopsy.discovery.search}. */
class Bundle {
    /**
     * @param month_abbreviation month abbreviation
     * @param day_of_month day of month
     * @param year year
     * @return <i>Week of </i>{@code month_abbreviation}<i> </i>{@code day_of_month}<i>, </i>{@code year}
     * @see DiscoveryKeyUtils
     */
    static String DiscoveryAttributes_ActivityDateGroupKey_getDisplayNameTemplate(Object month_abbreviation, Object day_of_month, Object year) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryAttributes.ActivityDateGroupKey.getDisplayNameTemplate", month_abbreviation, day_of_month, year);
    }
    /**
     * @return <i>Data Source</i>
     * @see DiscoveryAttributes
     */
    static String DiscoveryAttributes_GroupingAttributeType_datasource_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryAttributes.GroupingAttributeType.datasource.displayName");
    }
    /**
     * @return <i>File Type</i>
     * @see DiscoveryAttributes
     */
    static String DiscoveryAttributes_GroupingAttributeType_fileType_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryAttributes.GroupingAttributeType.fileType.displayName");
    }
    /**
     * @return <i>First Activity Date</i>
     * @see DiscoveryAttributes
     */
    static String DiscoveryAttributes_GroupingAttributeType_firstDate_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryAttributes.GroupingAttributeType.firstDate.displayName");
    }
    /**
     * @return <i>Past Occurrences</i>
     * @see DiscoveryAttributes
     */
    static String DiscoveryAttributes_GroupingAttributeType_frequency_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryAttributes.GroupingAttributeType.frequency.displayName");
    }
    /**
     * @return <i>Hash Set</i>
     * @see DiscoveryAttributes
     */
    static String DiscoveryAttributes_GroupingAttributeType_hash_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryAttributes.GroupingAttributeType.hash.displayName");
    }
    /**
     * @return <i>Interesting Item</i>
     * @see DiscoveryAttributes
     */
    static String DiscoveryAttributes_GroupingAttributeType_interestingItem_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryAttributes.GroupingAttributeType.interestingItem.displayName");
    }
    /**
     * @return <i>Keyword</i>
     * @see DiscoveryAttributes
     */
    static String DiscoveryAttributes_GroupingAttributeType_keywordList_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryAttributes.GroupingAttributeType.keywordList.displayName");
    }
    /**
     * @return <i>Final Activity Date</i>
     * @see DiscoveryAttributes
     */
    static String DiscoveryAttributes_GroupingAttributeType_lastDate_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryAttributes.GroupingAttributeType.lastDate.displayName");
    }
    /**
     * @return <i>None</i>
     * @see DiscoveryAttributes
     */
    static String DiscoveryAttributes_GroupingAttributeType_none_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryAttributes.GroupingAttributeType.none.displayName");
    }
    /**
     * @return <i>Object Detected</i>
     * @see DiscoveryAttributes
     */
    static String DiscoveryAttributes_GroupingAttributeType_object_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryAttributes.GroupingAttributeType.object.displayName");
    }
    /**
     * @return <i>Page Views</i>
     * @see DiscoveryAttributes
     */
    static String DiscoveryAttributes_GroupingAttributeType_pageViews_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryAttributes.GroupingAttributeType.pageViews.displayName");
    }
    /**
     * @return <i>Parent Folder</i>
     * @see DiscoveryAttributes
     */
    static String DiscoveryAttributes_GroupingAttributeType_parent_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryAttributes.GroupingAttributeType.parent.displayName");
    }
    /**
     * @return <i>Previous Notability</i>
     * @see DiscoveryAttributes
     */
    static String DiscoveryAttributes_GroupingAttributeType_previouslyNotable_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryAttributes.GroupingAttributeType.previouslyNotable.displayName");
    }
    /**
     * @return <i>File Size</i>
     * @see DiscoveryAttributes
     */
    static String DiscoveryAttributes_GroupingAttributeType_size_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryAttributes.GroupingAttributeType.size.displayName");
    }
    /**
     * @return <i>Tag</i>
     * @see DiscoveryAttributes
     */
    static String DiscoveryAttributes_GroupingAttributeType_tag_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryAttributes.GroupingAttributeType.tag.displayName");
    }
    /**
     * @return <i>Domain Category</i>
     * @see DiscoveryAttributes
     */
    static String DiscoveryAttributes_GroupingAttributeType_webCategory_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryAttributes.GroupingAttributeType.webCategory.displayName");
    }
    /**
     * @param Data_source_name Data source name
     * @param Data_source_ID Data source ID
     * @return {@code Data_source_name}<i>(ID: </i>{@code Data_source_ID}<i>)</i>
     * @see DiscoveryKeyUtils
     */
    static String DiscoveryKeyUtils_DataSourceGroupKey_datasourceAndID(Object Data_source_name, Object Data_source_ID) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryKeyUtils.DataSourceGroupKey.datasourceAndID", Data_source_name, Data_source_ID);
    }
    /**
     * @param Data_source_ID Data source ID
     * @return <i>Data source (ID: </i>{@code Data_source_ID}<i>)</i>
     * @see DiscoveryKeyUtils
     */
    static String DiscoveryKeyUtils_DataSourceGroupKey_idOnly(Object Data_source_ID) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryKeyUtils.DataSourceGroupKey.idOnly", Data_source_ID);
    }
    /**
     * @return <i>None</i>
     * @see DiscoveryKeyUtils
     */
    static String DiscoveryKeyUtils_FileTagGroupKey_noSets() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryKeyUtils.FileTagGroupKey.noSets");
    }
    /**
     * @return <i>None</i>
     * @see DiscoveryKeyUtils
     */
    static String DiscoveryKeyUtils_HashHitsGroupKey_noHashHits() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryKeyUtils.HashHitsGroupKey.noHashHits");
    }
    /**
     * @return <i>None</i>
     * @see DiscoveryKeyUtils
     */
    static String DiscoveryKeyUtils_InterestingItemGroupKey_noSets() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryKeyUtils.InterestingItemGroupKey.noSets");
    }
    /**
     * @return <i>None</i>
     * @see DiscoveryKeyUtils
     */
    static String DiscoveryKeyUtils_KeywordListGroupKey_noKeywords() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryKeyUtils.KeywordListGroupKey.noKeywords");
    }
    /**
     * @return <i>All Files</i>
     * @see DiscoveryKeyUtils
     */
    static String DiscoveryKeyUtils_NoGroupingGroupKey_allFiles() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryKeyUtils.NoGroupingGroupKey.allFiles");
    }
    /**
     * @return <i>None</i>
     * @see DiscoveryKeyUtils
     */
    static String DiscoveryKeyUtils_ObjectDetectedGroupKey_noSets() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DiscoveryKeyUtils.ObjectDetectedGroupKey.noSets");
    }
    /**
     * @param domain domain
     * @param artifactType artifactType
     * @return <i>Domain: </i>{@code domain}<i> ArtifactType: </i>{@code artifactType}
     * @see DomainSearchArtifactsRequest
     */
    static String DomainSearchArtifactsRequest_toString_text(Object domain, Object artifactType) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DomainSearchArtifactsRequest.toString.text", domain, artifactType);
    }
    /**
     * @return <i>Group Name</i>
     * @see Group
     */
    static String FileGroup_groupSortingAlgorithm_groupName_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileGroup.groupSortingAlgorithm.groupName.text");
    }
    /**
     * @return <i>Group Size</i>
     * @see Group
     */
    static String FileGroup_groupSortingAlgorithm_groupSize_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileGroup.groupSortingAlgorithm.groupSize.text");
    }
    /**
     * @param filters filters
     * @return <i>Hash set hits in set(s): </i>{@code filters}
     * @see SearchFiltering
     */
    static String FileSearchFiltering_HashSetFilter_desc(Object filters) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSearchFiltering.HashSetFilter.desc", filters);
    }
    /**
     * @return <i>which are not known</i>
     * @see SearchFiltering
     */
    static String FileSearchFiltering_KnownFilter_desc() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSearchFiltering.KnownFilter.desc");
    }
    /**
     * @return <i>that were previously marked as notable</i>
     * @see SearchFiltering
     */
    static String FileSearchFiltering_PreviouslyNotableFilter_desc() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSearchFiltering.PreviouslyNotableFilter.desc");
    }
    /**
     * @param tag_names tag names
     * @return <i>Tagged </i>{@code tag_names}
     * @see SearchFiltering
     */
    static String FileSearchFiltering_TagsFilter_desc(Object tag_names) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSearchFiltering.TagsFilter.desc", tag_names);
    }
    /**
     * @return <i>, </i>
     * @see SearchFiltering
     */
    static String FileSearchFiltering_TagsFilter_or() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSearchFiltering.TagsFilter.or");
    }
    /**
     * @return <i>that contain EXIF data</i>
     * @see SearchFiltering
     */
    static String FileSearchFiltering_UserCreatedFilter_desc() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSearchFiltering.UserCreatedFilter.desc");
    }
    /**
     * @return <i>, </i>
     * @see SearchFiltering
     */
    static String FileSearchFiltering_concatenateSetNamesForDisplay_comma() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSearchFiltering.concatenateSetNamesForDisplay.comma");
    }
    /**
     * @return <i>No bytes read for document, unable to display preview.</i>
     * @see FileSearch
     */
    static String FileSearch_documentSummary_noBytes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSearch.documentSummary.noBytes");
    }
    /**
     * @return <i>No preview available.</i>
     * @see FileSearch
     */
    static String FileSearch_documentSummary_noPreview() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSearch.documentSummary.noPreview");
    }
    /**
     * @return <i>Last Activity Date</i>
     * @see ResultsSorter
     */
    static String FileSorter_SortingMethod_activity_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSorter.SortingMethod.activity.displayName");
    }
    /**
     * @return <i>Data Source</i>
     * @see ResultsSorter
     */
    static String FileSorter_SortingMethod_datasource_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSorter.SortingMethod.datasource.displayName");
    }
    /**
     * @return <i>Domain Name</i>
     * @see ResultsSorter
     */
    static String FileSorter_SortingMethod_domain_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSorter.SortingMethod.domain.displayName");
    }
    /**
     * @return <i>File Downloads</i>
     * @see ResultsSorter
     */
    static String FileSorter_SortingMethod_downloads_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSorter.SortingMethod.downloads.displayName");
    }
    /**
     * @return <i>File Name</i>
     * @see ResultsSorter
     */
    static String FileSorter_SortingMethod_filename_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSorter.SortingMethod.filename.displayName");
    }
    /**
     * @return <i>File Size</i>
     * @see ResultsSorter
     */
    static String FileSorter_SortingMethod_filesize_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSorter.SortingMethod.filesize.displayName");
    }
    /**
     * @return <i>File Type</i>
     * @see ResultsSorter
     */
    static String FileSorter_SortingMethod_filetype_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSorter.SortingMethod.filetype.displayName");
    }
    /**
     * @return <i>Central Repo Frequency</i>
     * @see ResultsSorter
     */
    static String FileSorter_SortingMethod_frequency_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSorter.SortingMethod.frequency.displayName");
    }
    /**
     * @return <i>Full Path</i>
     * @see ResultsSorter
     */
    static String FileSorter_SortingMethod_fullPath_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSorter.SortingMethod.fullPath.displayName");
    }
    /**
     * @return <i>Keyword List Names</i>
     * @see ResultsSorter
     */
    static String FileSorter_SortingMethod_keywordlist_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSorter.SortingMethod.keywordlist.displayName");
    }
    /**
     * @return <i>Page Views</i>
     * @see ResultsSorter
     */
    static String FileSorter_SortingMethod_pageViews_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSorter.SortingMethod.pageViews.displayName");
    }
    /**
     * @return <i>Uncategorized</i>
     * @see ResultDomain
     */
    static String ResultDomain_getDefaultCategory() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ResultDomain_getDefaultCategory");
    }
    /**
     * @return <i>Unknown</i>
     * @see ResultDomain
     */
    static String ResultDomain_noAccountTypes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ResultDomain_noAccountTypes");
    }
    /**
     * @param significanceDisplayName significanceDisplayName
     * @return <i>Has an </i>{@code significanceDisplayName}<i> analysis result score</i>
     * @see ResultFile
     */
    static String ResultFile_updateScoreAndDescription_description(Object significanceDisplayName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ResultFile_updateScoreAndDescription_description", significanceDisplayName);
    }
    /**
     * @return <i>Domain</i>
     * @see SearchData
     */
    static String SearchData_AttributeType_Domain_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.AttributeType.Domain.displayName");
    }
    /**
     * @return <i>: 100KB-1MB</i>
     * @see SearchData
     */
    static String SearchData_FileSize_100kbto1mb() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileSize.100kbto1mb");
    }
    /**
     * @return <i>: 100MB-1GB</i>
     * @see SearchData
     */
    static String SearchData_FileSize_100mbto1gb() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileSize.100mbto1gb");
    }
    /**
     * @return <i>: 10GB+</i>
     * @see SearchData
     */
    static String SearchData_FileSize_10PlusGb() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileSize.10PlusGb");
    }
    /**
     * @return <i>: 16-100KB</i>
     * @see SearchData
     */
    static String SearchData_FileSize_16kbto100kb() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileSize.16kbto100kb");
    }
    /**
     * @return <i>: 1-5GB</i>
     * @see SearchData
     */
    static String SearchData_FileSize_1gbto5gb() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileSize.1gbto5gb");
    }
    /**
     * @return <i>: 1-50MB</i>
     * @see SearchData
     */
    static String SearchData_FileSize_1mbto50mb() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileSize.1mbto50mb");
    }
    /**
     * @return <i>: 200MB+</i>
     * @see SearchData
     */
    static String SearchData_FileSize_200PlusMb() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileSize.200PlusMb");
    }
    /**
     * @return <i>: 500KB-100MB</i>
     * @see SearchData
     */
    static String SearchData_FileSize_500kbto100mb() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileSize.500kbto100mb");
    }
    /**
     * @return <i>: 50-200MB</i>
     * @see SearchData
     */
    static String SearchData_FileSize_50mbto200mb() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileSize.50mbto200mb");
    }
    /**
     * @return <i>: 5-10GB</i>
     * @see SearchData
     */
    static String SearchData_FileSize_5gbto10gb() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileSize.5gbto10gb");
    }
    /**
     * @return <i>Large</i>
     * @see SearchData
     */
    static String SearchData_FileSize_LARGE_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileSize.LARGE.displayName");
    }
    /**
     * @return <i>Medium</i>
     * @see SearchData
     */
    static String SearchData_FileSize_MEDIUM_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileSize.MEDIUM.displayName");
    }
    /**
     * @return <i>Small</i>
     * @see SearchData
     */
    static String SearchData_FileSize_SMALL_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileSize.SMALL.displayName");
    }
    /**
     * @return <i>XLarge</i>
     * @see SearchData
     */
    static String SearchData_FileSize_XLARGE_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileSize.XLARGE.displayName");
    }
    /**
     * @return <i>XSmall</i>
     * @see SearchData
     */
    static String SearchData_FileSize_XSMALL_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileSize.XSMALL.displayName");
    }
    /**
     * @return <i>XXLarge</i>
     * @see SearchData
     */
    static String SearchData_FileSize_XXLARGE_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileSize.XXLARGE.displayName");
    }
    /**
     * @return <i>: 0-16KB</i>
     * @see SearchData
     */
    static String SearchData_FileSize_upTo16kb() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileSize.upTo16kb");
    }
    /**
     * @return <i>: 0-500KB</i>
     * @see SearchData
     */
    static String SearchData_FileSize_upTo500kb() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileSize.upTo500kb");
    }
    /**
     * @return <i>Audio</i>
     * @see SearchData
     */
    static String SearchData_FileType_Audio_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileType.Audio.displayName");
    }
    /**
     * @return <i>Document</i>
     * @see SearchData
     */
    static String SearchData_FileType_Documents_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileType.Documents.displayName");
    }
    /**
     * @return <i>Executable</i>
     * @see SearchData
     */
    static String SearchData_FileType_Executables_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileType.Executables.displayName");
    }
    /**
     * @return <i>Image</i>
     * @see SearchData
     */
    static String SearchData_FileType_Image_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileType.Image.displayName");
    }
    /**
     * @return <i>Other/Unknown</i>
     * @see SearchData
     */
    static String SearchData_FileType_Other_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileType.Other.displayName");
    }
    /**
     * @return <i>Video</i>
     * @see SearchData
     */
    static String SearchData_FileType_Video_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.FileType.Video.displayName");
    }
    /**
     * @return <i>Common (11 - 100)</i>
     * @see SearchData
     */
    static String SearchData_Frequency_common_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.Frequency.common.displayName");
    }
    /**
     * @return <i>Known (NSRL)</i>
     * @see SearchData
     */
    static String SearchData_Frequency_known_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.Frequency.known.displayName");
    }
    /**
     * @return <i>Rare (2-10)</i>
     * @see SearchData
     */
    static String SearchData_Frequency_rare_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.Frequency.rare.displayName");
    }
    /**
     * @return <i>Unique (1)</i>
     * @see SearchData
     */
    static String SearchData_Frequency_unique_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.Frequency.unique.displayName");
    }
    /**
     * @return <i>Unknown</i>
     * @see SearchData
     */
    static String SearchData_Frequency_unknown_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.Frequency.unknown.displayName");
    }
    /**
     * @return <i>Very Common (100+)</i>
     * @see SearchData
     */
    static String SearchData_Frequency_verycommon_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.Frequency.verycommon.displayName");
    }
    /**
     * @return <i>1000+ page views</i>
     * @see SearchData
     */
    static String SearchData_PageViews_over1000() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.PageViews.over1000");
    }
    /**
     * @param minValue minValue
     * @param maxValue maxValue
     * @return {@code minValue}<i>-</i>{@code maxValue}<i> page views</i>
     * @see SearchData
     */
    static String SearchData_PageViews_rangeTemplate(Object minValue, Object maxValue) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.PageViews.rangeTemplate", minValue, maxValue);
    }
    /**
     * @return <i>Interesting</i>
     * @see SearchData
     */
    static String SearchData_Score_interesting_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.Score.interesting.displayName");
    }
    /**
     * @return <i>Notable</i>
     * @see SearchData
     */
    static String SearchData_Score_notable_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.Score.notable.displayName");
    }
    /**
     * @return <i>Unknown</i>
     * @see SearchData
     */
    static String SearchData_Score_unknown_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.Score.unknown.displayName");
    }
    /**
     * @return <i>Previously Not Notable</i>
     * @see SearchData
     */
    static String SearchData_notPrevNotable_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.notPrevNotable.displayName");
    }
    /**
     * @return <i>Previously Notable</i>
     * @see SearchData
     */
    static String SearchData_prevNotable_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchData.prevNotable.displayName");
    }
    /**
     * @param Data_source_name Data source name
     * @param Data_source_ID Data source ID
     * @return {@code Data_source_name}<i>(</i>{@code Data_source_ID}<i>)</i>
     * @see SearchFiltering
     */
    static String SearchFiltering_DataSourceFilter_datasource(Object Data_source_name, Object Data_source_ID) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.DataSourceFilter.datasource", Data_source_name, Data_source_ID);
    }
    /**
     * @param filters filters
     * @return <i>Data source(s): </i>{@code filters}
     * @see SearchFiltering
     */
    static String SearchFiltering_DataSourceFilter_desc(Object filters) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.DataSourceFilter.desc", filters);
    }
    /**
     * @return <i>, </i>
     * @see SearchFiltering
     */
    static String SearchFiltering_DataSourceFilter_or() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.DataSourceFilter.or");
    }
    /**
     * @param filters filters
     * @return <i>Type: </i>{@code filters}
     * @see SearchFiltering
     */
    static String SearchFiltering_FileTypeFilter_desc(Object filters) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.FileTypeFilter.desc", filters);
    }
    /**
     * @return <i>, </i>
     * @see SearchFiltering
     */
    static String SearchFiltering_FileTypeFilter_or() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.FileTypeFilter.or");
    }
    /**
     * @param filters filters
     * @return <i>Past occurrences: </i>{@code filters}
     * @see SearchFiltering
     */
    static String SearchFiltering_FrequencyFilter_desc(Object filters) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.FrequencyFilter.desc", filters);
    }
    /**
     * @return <i>, </i>
     * @see SearchFiltering
     */
    static String SearchFiltering_FrequencyFilter_or() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.FrequencyFilter.or");
    }
    /**
     * @param filters filters
     * @return <i>Interesting item hits in set(s): </i>{@code filters}
     * @see SearchFiltering
     */
    static String SearchFiltering_InterestingItemSetFilter_desc(Object filters) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.InterestingItemSetFilter.desc", filters);
    }
    /**
     * @param filters filters
     * @return <i>Keywords in list(s): </i>{@code filters}
     * @see SearchFiltering
     */
    static String SearchFiltering_KeywordListFilter_desc(Object filters) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.KeywordListFilter.desc", filters);
    }
    /**
     * @return <i>Only domains with known account type</i>
     * @see SearchFiltering
     */
    static String SearchFiltering_KnownAccountTypeFilter_desc() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.KnownAccountTypeFilter.desc");
    }
    /**
     * @param filters filters
     * @return <i>Objects detected in set(s): </i>{@code filters}
     * @see SearchFiltering
     */
    static String SearchFiltering_ObjectDetectionFilter_desc(Object filters) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.ObjectDetectionFilter.desc", filters);
    }
    /**
     * @param filters filters
     * @return <i>Paths matching: </i>{@code filters}
     * @see SearchFiltering
     */
    static String SearchFiltering_ParentFilter_desc(Object filters) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.ParentFilter.desc", filters);
    }
    /**
     * @return <i>(exact match)</i>
     * @see SearchFiltering
     */
    static String SearchFiltering_ParentFilter_exact() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.ParentFilter.exact");
    }
    /**
     * @return <i>(excluded)</i>
     * @see SearchFiltering
     */
    static String SearchFiltering_ParentFilter_excluded() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.ParentFilter.excluded");
    }
    /**
     * @return <i>(included)</i>
     * @see SearchFiltering
     */
    static String SearchFiltering_ParentFilter_included() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.ParentFilter.included");
    }
    /**
     * @return <i>, </i>
     * @see SearchFiltering
     */
    static String SearchFiltering_ParentFilter_or() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.ParentFilter.or");
    }
    /**
     * @return <i>(substring)</i>
     * @see SearchFiltering
     */
    static String SearchFiltering_ParentFilter_substring() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.ParentFilter.substring");
    }
    /**
     * @return <i> (exclude)</i>
     * @see SearchFiltering
     */
    static String SearchFiltering_ParentSearchTerm_excludeString() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.ParentSearchTerm.excludeString");
    }
    /**
     * @return <i> (exact)</i>
     * @see SearchFiltering
     */
    static String SearchFiltering_ParentSearchTerm_fullString() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.ParentSearchTerm.fullString");
    }
    /**
     * @return <i> (include)</i>
     * @see SearchFiltering
     */
    static String SearchFiltering_ParentSearchTerm_includeString() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.ParentSearchTerm.includeString");
    }
    /**
     * @return <i> (substring)</i>
     * @see SearchFiltering
     */
    static String SearchFiltering_ParentSearchTerm_subString() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.ParentSearchTerm.subString");
    }
    /**
     * @return <i>Previously marked as notable in central repository</i>
     * @see SearchFiltering
     */
    static String SearchFiltering_PreviouslyNotableFilter_desc() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.PreviouslyNotableFilter.desc");
    }
    /**
     * @param filters filters
     * @return <i>Score(s) of : </i>{@code filters}
     * @see SearchFiltering
     */
    static String SearchFiltering_ScoreFilter_desc(Object filters) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.ScoreFilter.desc", filters);
    }
    /**
     * @param filters filters
     * @return <i>Size(s): </i>{@code filters}
     * @see SearchFiltering
     */
    static String SearchFiltering_SizeFilter_desc(Object filters) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.SizeFilter.desc", filters);
    }
    /**
     * @return <i>, </i>
     * @see SearchFiltering
     */
    static String SearchFiltering_SizeFilter_or() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.SizeFilter.or");
    }
    /**
     * @param artifactTypes artifactTypes
     * @return <i>Result type(s): </i>{@code artifactTypes}
     * @see SearchFiltering
     */
    static String SearchFiltering_artifactTypeFilter_desc(Object artifactTypes) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.artifactTypeFilter.desc", artifactTypes);
    }
    /**
     * @return <i>, </i>
     * @see SearchFiltering
     */
    static String SearchFiltering_artifactTypeFilter_or() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.artifactTypeFilter.or");
    }
    /**
     * @param startDate startDate
     * @return <i>after: </i>{@code startDate}
     * @see SearchFiltering
     */
    static String SearchFiltering_dateRangeFilter_after(Object startDate) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.dateRangeFilter.after", startDate);
    }
    /**
     * @return <i> and </i>
     * @see SearchFiltering
     */
    static String SearchFiltering_dateRangeFilter_and() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.dateRangeFilter.and");
    }
    /**
     * @param endDate endDate
     * @return <i>before: </i>{@code endDate}
     * @see SearchFiltering
     */
    static String SearchFiltering_dateRangeFilter_before(Object endDate) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.dateRangeFilter.before", endDate);
    }
    /**
     * @return <i>Activity date </i>
     * @see SearchFiltering
     */
    static String SearchFiltering_dateRangeFilter_lable() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchFiltering.dateRangeFilter.lable");
    }
    /**
     * @return <i>Error trying to extract text from file.</i>
     * @see SummaryHelpers
     */
    static String SummaryHelper_documentSummary_unable_to_read() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SummaryHelper.documentSummary.unable.to.read");
    }
    private Bundle() {}
}
