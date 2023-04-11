package org.sleuthkit.autopsy.contentviewers.analysisresults;
/** Localizable strings for {@link org.sleuthkit.autopsy.contentviewers.analysisresults}. */
class Bundle {
    /**
     * @return <i>Aggregate Score</i>
     * @see AnalysisResultsContentPanel
     */
    static String AnalysisResultsContentPanel_aggregateScore_displayKey() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AnalysisResultsContentPanel_aggregateScore_displayKey");
    }
    /**
     * @return <i>Item</i>
     * @see AnalysisResultsContentPanel
     */
    static String AnalysisResultsContentPanel_content_displayKey() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AnalysisResultsContentPanel_content_displayKey");
    }
    /**
     * @param analysisResultsNumber analysisResultsNumber
     * @return <i>Analysis Result </i>{@code analysisResultsNumber}
     * @see AnalysisResultsContentPanel
     */
    static String AnalysisResultsContentPanel_result_headerKey(Object analysisResultsNumber) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AnalysisResultsContentPanel_result_headerKey", analysisResultsNumber);
    }
    /**
     * @return <i>There was an error loading results.</i>
     * @see AnalysisResultsContentViewer
     */
    static String AnalysisResultsContentViewer_setNode_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AnalysisResultsContentViewer_setNode_errorMessage");
    }
    /**
     * @return <i>Loading...</i>
     * @see AnalysisResultsContentViewer
     */
    static String AnalysisResultsContentViewer_setNode_loadingMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AnalysisResultsContentViewer_setNode_loadingMessage");
    }
    /**
     * @return <i>Analysis Results</i>
     * @see AnalysisResultsContentViewer
     */
    static String AnalysisResultsContentViewer_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AnalysisResultsContentViewer_title");
    }
    /**
     * @return <i>Viewer for Analysis Results related to the selected node.</i>
     * @see AnalysisResultsContentViewer
     */
    static String AnalysisResultsContentViewer_tooltip() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AnalysisResultsContentViewer_tooltip");
    }
    /**
     * @return <i>Conclusion</i>
     * @see AnalysisResultsViewModel
     */
    static String AnalysisResultsViewModel_displayAttributes_conclusion() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AnalysisResultsViewModel_displayAttributes_conclusion");
    }
    /**
     * @return <i>Configuration</i>
     * @see AnalysisResultsViewModel
     */
    static String AnalysisResultsViewModel_displayAttributes_configuration() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AnalysisResultsViewModel_displayAttributes_configuration");
    }
    /**
     * @return <i>Score</i>
     * @see AnalysisResultsViewModel
     */
    static String AnalysisResultsViewModel_displayAttributes_score() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AnalysisResultsViewModel_displayAttributes_score");
    }
    /**
     * @return <i>Type</i>
     * @see AnalysisResultsViewModel
     */
    static String AnalysisResultsViewModel_displayAttributes_type() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AnalysisResultsViewModel_displayAttributes_type");
    }
    private Bundle() {}
}
