package org.sleuthkit.autopsy.commonpropertiessearch;
/** Localizable strings for {@link org.sleuthkit.autopsy.commonpropertiessearch}. */
class Bundle {
    /**
     * @return <i>All File Categories</i>
     * @see AbstractCommonAttributeSearcher
     */
    static String AbstractCommonFilesMetadataBuilder_buildCategorySelectionString_all() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AbstractCommonFilesMetadataBuilder.buildCategorySelectionString.all");
    }
    /**
     * @return <i>Documents</i>
     * @see AbstractCommonAttributeSearcher
     */
    static String AbstractCommonFilesMetadataBuilder_buildCategorySelectionString_doc() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AbstractCommonFilesMetadataBuilder.buildCategorySelectionString.doc");
    }
    /**
     * @return <i>Media</i>
     * @see AbstractCommonAttributeSearcher
     */
    static String AbstractCommonFilesMetadataBuilder_buildCategorySelectionString_media() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AbstractCommonFilesMetadataBuilder.buildCategorySelectionString.media");
    }
    /**
     * @param threshold_percent threshold percent
     * @return <i>, Threshold </i>{@code threshold_percent}<i>%</i>
     * @see AbstractCommonAttributeSearcher
     */
    static String AbstractCommonFilesMetadataBuilder_getPercentFilter_thresholdPercent(Object threshold_percent) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AbstractCommonFilesMetadataBuilder.getPercentFilter.thresholdPercent", threshold_percent);
    }
    /**
     * @param attr_type attr type
     * @param threshold_string threshold string
     * @return <i>Common Properties (All Central Repository Cases, </i>{@code attr_type}{@code threshold_string}<i>)</i>
     * @see AllInterCaseCommonAttributeSearcher
     */
    static String AllInterCaseCommonAttributeSearcher_buildTabTitle_titleInterAll(Object attr_type, Object threshold_string) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllInterCaseCommonAttributeSearcher.buildTabTitle.titleInterAll", attr_type, threshold_string);
    }
    /**
     * @param build_category build category
     * @param threshold_string threshold string
     * @return <i>Common Properties (All Data Sources, </i>{@code build_category}{@code threshold_string}<i>)</i>
     * @see AllIntraCaseCommonAttributeSearcher
     */
    static String AllIntraCaseCommonAttributeSearcher_buildTabTitle_titleIntraAll(Object build_category, Object threshold_string) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllIntraCaseCommonAttributeSearcher.buildTabTitle.titleIntraAll", build_category, threshold_string);
    }
    /**
     * @param number_of_datasources number of datasources
     * @return <i>The current Central Repository contains </i>{@code number_of_datasources}<i> data source(s).</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_dataSourcesLabel_text(Object number_of_datasources) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.dataSourcesLabel.text", number_of_datasources);
    }
    /**
     * @return <i>Unexpected Exception loading DataSources.</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_exception() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.exception");
    }
    /**
     * @return <i>Find Common Properties</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_frame_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.frame.title");
    }
    /**
     * @return <i><br><br> Continue with search anyway?</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_incompleteResults_continueText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.incompleteResults.continueText");
    }
    /**
     * @return <i>Results may be incomplete. Not all data sources in the current case were ingested into the current Central Repository. The following data sources have not been processed:</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_incompleteResults_introText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.incompleteResults.introText");
    }
    /**
     * @return <i>Search may be incomplete</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_incompleteResults_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.incompleteResults.title");
    }
    /**
     * @return <i>Curren Case Options</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_intraCasePanel_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.intraCasePanel.title");
    }
    /**
     * @return <i>Unexpected exception running Find Common Properties.</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_search_done_exception() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.search.done.exception");
    }
    /**
     * @return <i>Something went wrong finding common properties.</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_search_done_interupted() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.search.done.interupted");
    }
    /**
     * @return <i>Unable to open case file.</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_search_done_noCurrentCaseException() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.search.done.noCurrentCaseException");
    }
    /**
     * @return <i>No results found.</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_search_done_noResults() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.search.done.noResults");
    }
    /**
     * @return <i>Displaying Common Properties Results.</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_search_done_searchProgressDisplay() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.search.done.searchProgressDisplay");
    }
    /**
     * @return <i>Gathering Common Properties Results.</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_search_done_searchProgressGathering() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.search.done.searchProgressGathering");
    }
    /**
     * @return <i>Unable to query db for properties or data sources.</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_search_done_sqlException() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.search.done.sqlException");
    }
    /**
     * @return <i>Unable to run query against DB.</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_search_done_tskCoreException() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.search.done.tskCoreException");
    }
    /**
     * @return <i>Common Properties Results</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_search_results_pathText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.search.results.pathText");
    }
    /**
     * @return <i>Unexpected exception loading cases.</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_setupCases_done_exeutionException() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.setupCases.done.exeutionException");
    }
    /**
     * @return <i>Something went wrong building the Common Files Search dialog box.</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_setupCases_done_interruptedException() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.setupCases.done.interruptedException");
    }
    /**
     * @return <i>Unexpected exception loading data sources.</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_setupDataSources_done_exception() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.setupDataSources.done.exception");
    }
    /**
     * @return <i>Something went wrong building the Common Files Search dialog box.</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_setupDataSources_done_interupted() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.setupDataSources.done.interupted");
    }
    /**
     * @return <i>Unable to open case file.</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_setupDataSources_done_noCurrentCaseException() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.setupDataSources.done.noCurrentCaseException");
    }
    /**
     * @return <i>Unable to query db for data sources.</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_setupDataSources_done_sqlException() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.setupDataSources.done.sqlException");
    }
    /**
     * @return <i>Unable to run query against DB.</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_setupDataSources_done_tskCoreException() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.setupDataSources.done.tskCoreException");
    }
    /**
     * @return <i>No data sources were found.</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_setupDataSources_updateUi_noDataSources() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.setupDataSources.updateUi.noDataSources");
    }
    /**
     * @return <i>Common Property Panel</i>
     * @see CommonAttributePanel
     */
    static String CommonAttributePanel_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributePanel.title");
    }
    /**
     * @return <i>Find Common Properties</i>
     * @see CommonAttributeSearchAction
     */
    static String CommonAttributeSearchAction_getName_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributeSearchAction.getName.text");
    }
    /**
     * @return <i><br>  - The current case is not in the Central Repository.</i>
     * @see CommonAttributeSearchAction
     */
    static String CommonAttributeSearchAction_openPanel_caseNotInCentralRepo() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributeSearchAction.openPanel.caseNotInCentralRepo");
    }
    /**
     * @return <i><br>  - The Central Repository is disabled.</i>
     * @see CommonAttributeSearchAction
     */
    static String CommonAttributeSearchAction_openPanel_centralRepoDisabled() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributeSearchAction.openPanel.centralRepoDisabled");
    }
    /**
     * @return <i><br>  - The Central Repository configuration is invalid.</i>
     * @see CommonAttributeSearchAction
     */
    static String CommonAttributeSearchAction_openPanel_centralRepoInvalid() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributeSearchAction.openPanel.centralRepoInvalid");
    }
    /**
     * @return <i>The find common properties feature is not available because:</i>
     * @see CommonAttributeSearchAction
     */
    static String CommonAttributeSearchAction_openPanel_intro() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributeSearchAction.openPanel.intro");
    }
    /**
     * @return <i><br>  - No case is open.</i>
     * @see CommonAttributeSearchAction
     */
    static String CommonAttributeSearchAction_openPanel_noCaseOpen() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributeSearchAction.openPanel.noCaseOpen");
    }
    /**
     * @return <i><br>  - Fewer than 2 cases exist in the Central Repository.</i>
     * @see CommonAttributeSearchAction
     */
    static String CommonAttributeSearchAction_openPanel_notEnoughCases() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributeSearchAction.openPanel.notEnoughCases");
    }
    /**
     * @return <i><br>  - There are not multiple data sources in the current case.</i>
     * @see CommonAttributeSearchAction
     */
    static String CommonAttributeSearchAction_openPanel_notEnoughDataSources() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributeSearchAction.openPanel.notEnoughDataSources");
    }
    /**
     * @return <i><br><br>Address one of these issues to enable this feature.</i>
     * @see CommonAttributeSearchAction
     */
    static String CommonAttributeSearchAction_openPanel_resolution() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributeSearchAction.openPanel.resolution");
    }
    /**
     * @return <i>Value: %s</i>
     * @see CommonAttributeValueNode
     */
    static String CommonAttributeValueNode_CommonAttributeValueNode_format() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonAttributeValueNode.CommonAttributeValueNode.format");
    }
    /**
     * @return <i>Common Files</i>
     * @see CommonAttributeSearchResultRootNode
     */
    static String CommonFilesNode_getName_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonFilesNode.getName.text");
    }
    /**
     * @return <i>Case</i>
     * @see CommonAttributesSearchResultsViewerTable
     */
    static String CommonFilesSearchResultsViewerTable_caseColLbl() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonFilesSearchResultsViewerTable.caseColLbl");
    }
    /**
     * @return <i>Data Source</i>
     * @see CommonAttributesSearchResultsViewerTable
     */
    static String CommonFilesSearchResultsViewerTable_dataSourceColLbl() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonFilesSearchResultsViewerTable.dataSourceColLbl");
    }
    /**
     * @return <i>Instances</i>
     * @see CommonAttributesSearchResultsViewerTable
     */
    static String CommonFilesSearchResultsViewerTable_instancesColLbl() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonFilesSearchResultsViewerTable.instancesColLbl");
    }
    /**
     * @return <i>Parent Path in Current Case</i>
     * @see CommonAttributesSearchResultsViewerTable
     */
    static String CommonFilesSearchResultsViewerTable_localPath() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonFilesSearchResultsViewerTable.localPath");
    }
    /**
     * @return <i> </i>
     * @see CommonAttributesSearchResultsViewerTable
     */
    static String CommonFilesSearchResultsViewerTable_noDescText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonFilesSearchResultsViewerTable.noDescText");
    }
    /**
     * @return <i>Parent Path</i>
     * @see CommonAttributesSearchResultsViewerTable
     */
    static String CommonFilesSearchResultsViewerTable_pathColLbl() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonFilesSearchResultsViewerTable.pathColLbl");
    }
    /**
     * @return <i>Value</i>
     * @see CommonAttributesSearchResultsViewerTable
     */
    static String CommonFilesSearchResultsViewerTable_valueColLbl() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommonFilesSearchResultsViewerTable.valueColLbl");
    }
    /**
     * @return <i> </i>
     * @see InstanceCountNode
     */
    static String InstanceCountNode_createSheet_noDescription() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "InstanceCountNode.createSheet.noDescription");
    }
    /**
     * @return <i>Exists in %s data sources (%s)</i>
     * @see InstanceCountNode
     */
    static String InstanceCountNode_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "InstanceCountNode.displayName");
    }
    /**
     * @param case_name case name
     * @param attr_type attr type
     * @param threshold_string threshold string
     * @return <i>Common Properties (Central Repository Case: </i>{@code case_name}<i>, </i>{@code attr_type}{@code threshold_string}<i>)</i>
     * @see SingleInterCaseCommonAttributeSearcher
     */
    static String SingleInterCaseCommonAttributeSearcher_buildTabTitle_titleInterSingle(Object case_name, Object attr_type, Object threshold_string) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SingleInterCaseCommonAttributeSearcher.buildTabTitle.titleInterSingle", case_name, attr_type, threshold_string);
    }
    /**
     * @param data_source_name data source name
     * @param build_category build category
     * @param threshold_string threshold string
     * @return <i>Common Properties (Data Source: </i>{@code data_source_name}<i>, </i>{@code build_category}{@code threshold_string}<i>)</i>
     * @see SingleIntraCaseCommonAttributeSearcher
     */
    static String SingleIntraCaseCommonAttributeSearcher_buildTabTitle_titleIntraSingle(Object data_source_name, Object build_category, Object threshold_string) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SingleIntraCaseCommonAttributeSearcher.buildTabTitle.titleIntraSingle", data_source_name, build_category, threshold_string);
    }
    /**
     * @return <i>No file categories are included in the search.</i>
     * @see UserInputErrorManager
     */
    static String UserInputErrorManager_categories() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UserInputErrorManager.categories");
    }
    /**
     * @return <i>Invalid Frequency Percentage: 0 &lt; % &lt; 100.</i>
     * @see UserInputErrorManager
     */
    static String UserInputErrorManager_frequency() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UserInputErrorManager.frequency");
    }
    /**
     * @return <i> </i>
     * @see CommonAttributeValueNode
     */
    static String ValueNode_createSheet_noDescription() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ValueNode.createSheet.noDescription");
    }
    private Bundle() {}
}
