package org.sleuthkit.autopsy.filesearch;
/** Localizable strings for {@link org.sleuthkit.autopsy.filesearch}. */
class Bundle {
    /**
     * @return <i>At least one data source must be selected.</i>
     * @see DataSourceFilter
     */
    static String DataSourceFilter_errorMessage_emptyDataSource() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataSourceFilter.errorMessage.emptyDataSource");
    }
    /**
     * @return <i>The end date should be after the start date.</i>
     * @see DateSearchFilter
     */
    static String DateSearchFilter_errorMessage_endDateBeforeStartDate() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DateSearchFilter.errorMessage.endDateBeforeStartDate");
    }
    /**
     * @return <i>At least one date type checkbox must be selected.</i>
     * @see DateSearchFilter
     */
    static String DateSearchFilter_errorMessage_noCheckboxSelected() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DateSearchFilter.errorMessage.noCheckboxSelected");
    }
    /**
     * @return <i>Search Was Cancelled</i>
     * @see FileSearchPanel
     */
    static String FileSearchPanel_cancelledSearch_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSearchPanel.cancelledSearch.text");
    }
    /**
     * @return <i>No results found.</i>
     * @see FileSearchPanel
     */
    static String FileSearchPanel_emptyNode_display_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSearchPanel.emptyNode.display.text");
    }
    /**
     * @return <i>Performing file search by attributes. Please wait.</i>
     * @see FileSearchPanel
     */
    static String FileSearchPanel_searchingNode_display_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSearchPanel.searchingNode.display.text");
    }
    /**
     * @return <i>File Search In Progress</i>
     * @see FileSearchPanel
     */
    static String FileSearchPanel_searchingPath_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSearchPanel.searchingPath.text");
    }
    /**
     * @return <i>Hash data is empty.</i>
     * @see HashSearchFilter
     */
    static String HashSearchFilter_errorMessage_emptyHash() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashSearchFilter.errorMessage.emptyHash");
    }
    /**
     * @return <i>MD5 contains invalid hex characters.</i>
     * @see HashSearchFilter
     */
    static String HashSearchFilter_errorMessage_wrongCharacter() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashSearchFilter.errorMessage.wrongCharacter");
    }
    /**
     * @param hash_data_length hash data length
     * @return <i>Input length(</i>{@code hash_data_length}<i>), doesn''t match the MD5 length(32).</i>
     * @see HashSearchFilter
     */
    static String HashSearchFilter_errorMessage_wrongLengthMd5(Object hash_data_length) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashSearchFilter.errorMessage.wrongLengthMd5", hash_data_length);
    }
    /**
     * @param hash_data_length hash data length
     * @return <i>Input length(</i>{@code hash_data_length}<i>), doesn''t match the SHA-256 length(64).</i>
     * @see HashSearchFilter
     */
    static String HashSearchFilter_errorMessage_wrongLengthSha256(Object hash_data_length) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashSearchFilter.errorMessage.wrongLengthSha256", hash_data_length);
    }
    /**
     * @return <i>At least one known status checkbox must be selected.</i>
     * @see KnownStatusSearchFilter
     */
    static String KnownStatusSearchFilter_errorMessage_noKnownStatusCheckboxSelected() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "KnownStatusSearchFilter.errorMessage.noKnownStatusCheckboxSelected");
    }
    /**
     * @return <i>At least one MIME type must be selected.</i>
     * @see MimeTypeFilter
     */
    static String MimeTypeFilter_errorMessage_emptyMimeType() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MimeTypeFilter.errorMessage.emptyMimeType");
    }
    /**
     * @return <i>Please input a name to search.</i>
     * @see NameSearchFilter
     */
    static String NameSearchFilter_errorMessage_emtpyName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "NameSearchFilter.errorMessage.emtpyName");
    }
    /**
     * @return <i>Search Result</i>
     * @see SearchNode
     */
    static String SearchNode_getName_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchNode.getName.text");
    }
    /**
     * @return <i>Input size data is a negative number.</i>
     * @see SizeSearchFilter
     */
    static String SizeSearchFilter_errorMessage_nonNegativeNumber() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SizeSearchFilter.errorMessage.nonNegativeNumber");
    }
    /**
     * @return <i>Input size data is not a number.</i>
     * @see SizeSearchFilter
     */
    static String SizeSearchFilter_errorMessage_notANumber() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SizeSearchFilter.errorMessage.notANumber");
    }
    private Bundle() {}
}
