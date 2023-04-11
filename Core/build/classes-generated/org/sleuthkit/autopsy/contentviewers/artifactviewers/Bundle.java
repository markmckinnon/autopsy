package org.sleuthkit.autopsy.contentviewers.artifactviewers;
/** Localizable strings for {@link org.sleuthkit.autopsy.contentviewers.artifactviewers}. */
class Bundle {
    /**
     * @return <i>Source</i>
     * @see CallLogArtifactViewer
     */
    static String CallLogArtifactViewer_heading_Source() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CallLogArtifactViewer_heading_Source");
    }
    /**
     * @return <i>Metadata</i>
     * @see CallLogArtifactViewer
     */
    static String CallLogArtifactViewer_heading_metadata() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CallLogArtifactViewer_heading_metadata");
    }
    /**
     * @return <i>Other Attributes</i>
     * @see CallLogArtifactViewer
     */
    static String CallLogArtifactViewer_heading_others() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CallLogArtifactViewer_heading_others");
    }
    /**
     * @return <i>Parties</i>
     * @see CallLogArtifactViewer
     */
    static String CallLogArtifactViewer_heading_parties() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CallLogArtifactViewer_heading_parties");
    }
    /**
     * @return <i>Data Source</i>
     * @see CallLogArtifactViewer
     */
    static String CallLogArtifactViewer_label_datasource() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CallLogArtifactViewer_label_datasource");
    }
    /**
     * @return <i>Date</i>
     * @see CallLogArtifactViewer
     */
    static String CallLogArtifactViewer_label_date() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CallLogArtifactViewer_label_date");
    }
    /**
     * @return <i>Direction</i>
     * @see CallLogArtifactViewer
     */
    static String CallLogArtifactViewer_label_direction() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CallLogArtifactViewer_label_direction");
    }
    /**
     * @return <i>Duration</i>
     * @see CallLogArtifactViewer
     */
    static String CallLogArtifactViewer_label_duration() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CallLogArtifactViewer_label_duration");
    }
    /**
     * @return <i>From</i>
     * @see CallLogArtifactViewer
     */
    static String CallLogArtifactViewer_label_from() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CallLogArtifactViewer_label_from");
    }
    /**
     * @return <i>Host</i>
     * @see CallLogArtifactViewer
     */
    static String CallLogArtifactViewer_label_hostName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CallLogArtifactViewer_label_hostName");
    }
    /**
     * @return <i>To</i>
     * @see CallLogArtifactViewer
     */
    static String CallLogArtifactViewer_label_to() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CallLogArtifactViewer_label_to");
    }
    /**
     * @return <i>(Local)</i>
     * @see CallLogArtifactViewer
     */
    static String CallLogArtifactViewer_suffix_local() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CallLogArtifactViewer_suffix_local");
    }
    /**
     * @return <i>Unknown</i>
     * @see CallLogArtifactViewer
     */
    static String CallLogArtifactViewer_value_unknown() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CallLogArtifactViewer_value_unknown");
    }
    /**
     * @return <i>Enable Central Repository to view, create and edit personas.</i>
     * @see CallLogArtifactViewer
     */
    static String CalllogArtifactViewer_cr_disabled_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CalllogArtifactViewer_cr_disabled_message");
    }
    /**
     * @param contact_name contact name
     * @return <i>Contact: </i>{@code contact_name}
     * @see CommunicationArtifactViewerHelper
     */
    static String CommunicationArtifactViewerHelper_contact_label(Object contact_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommunicationArtifactViewerHelper_contact_label", contact_name);
    }
    /**
     * @return <i>Unknown</i>
     * @see CommunicationArtifactViewerHelper
     */
    static String CommunicationArtifactViewerHelper_contact_label_unknown() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommunicationArtifactViewerHelper_contact_label_unknown");
    }
    /**
     * @return <i>Copy</i>
     * @see CommunicationArtifactViewerHelper
     */
    static String CommunicationArtifactViewerHelper_menuitem_copy() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommunicationArtifactViewerHelper_menuitem_copy");
    }
    /**
     * @return <i>Create</i>
     * @see CommunicationArtifactViewerHelper
     */
    static String CommunicationArtifactViewerHelper_persona_button_create() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommunicationArtifactViewerHelper_persona_button_create");
    }
    /**
     * @return <i>View</i>
     * @see CommunicationArtifactViewerHelper
     */
    static String CommunicationArtifactViewerHelper_persona_button_view() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommunicationArtifactViewerHelper_persona_button_view");
    }
    /**
     * @return <i>Persona: </i>
     * @see CommunicationArtifactViewerHelper
     */
    static String CommunicationArtifactViewerHelper_persona_label() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommunicationArtifactViewerHelper_persona_label");
    }
    /**
     * @return <i>Searching...</i>
     * @see CommunicationArtifactViewerHelper
     */
    static String CommunicationArtifactViewerHelper_persona_searching() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommunicationArtifactViewerHelper_persona_searching");
    }
    /**
     * @return <i>Unknown</i>
     * @see CommunicationArtifactViewerHelper
     */
    static String CommunicationArtifactViewerHelper_persona_unknown() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CommunicationArtifactViewerHelper_persona_unknown");
    }
    /**
     * @return 
     * @see ContactArtifactViewer
     */
    static String ContactArtifactViewer_contactImage_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ContactArtifactViewer.contactImage.text");
    }
    /**
     * @return <i>Unknown</i>
     * @see ContactArtifactViewer
     */
    static String ContactArtifactViewer_contactname_unknown() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ContactArtifactViewer_contactname_unknown");
    }
    /**
     * @return <i>Enable Central Repository to view, create and edit personas.</i>
     * @see ContactArtifactViewer
     */
    static String ContactArtifactViewer_cr_disabled_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ContactArtifactViewer_cr_disabled_message");
    }
    /**
     * @return <i>Email</i>
     * @see ContactArtifactViewer
     */
    static String ContactArtifactViewer_emails_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ContactArtifactViewer_emails_header");
    }
    /**
     * @return <i>All accounts found.</i>
     * @see ContactArtifactViewer
     */
    static String ContactArtifactViewer_found_all_accounts_label() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ContactArtifactViewer_found_all_accounts_label");
    }
    /**
     * @return <i>Source</i>
     * @see ContactArtifactViewer
     */
    static String ContactArtifactViewer_heading_Source() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ContactArtifactViewer_heading_Source");
    }
    /**
     * @param accountIdentifer accountIdentifer
     * @return <i>Unable to find account(s) associated with contact </i>{@code accountIdentifer}<i> in the Central Repository.</i>
     * @see ContactArtifactViewer
     */
    static String ContactArtifactViewer_id_not_found_in_cr(Object accountIdentifer) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ContactArtifactViewer_id_not_found_in_cr", accountIdentifer);
    }
    /**
     * @return <i>Data Source</i>
     * @see ContactArtifactViewer
     */
    static String ContactArtifactViewer_label_datasource() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ContactArtifactViewer_label_datasource");
    }
    /**
     * @return <i>Host</i>
     * @see ContactArtifactViewer
     */
    static String ContactArtifactViewer_label_host() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ContactArtifactViewer_label_host");
    }
    /**
     * @return <i>Missing contact account</i>
     * @see ContactArtifactViewer
     */
    static String ContactArtifactViewer_missing_account_label() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ContactArtifactViewer_missing_account_label");
    }
    /**
     * @return <i>Other</i>
     * @see ContactArtifactViewer
     */
    static String ContactArtifactViewer_others_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ContactArtifactViewer_others_header");
    }
    /**
     * @return <i>Account found in Contact artifact</i>
     * @see ContactArtifactViewer
     */
    static String ContactArtifactViewer_persona_account_justification() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ContactArtifactViewer_persona_account_justification");
    }
    /**
     * @return <i>Create</i>
     * @see ContactArtifactViewer
     */
    static String ContactArtifactViewer_persona_button_new() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ContactArtifactViewer_persona_button_new");
    }
    /**
     * @return <i>View</i>
     * @see ContactArtifactViewer
     */
    static String ContactArtifactViewer_persona_button_view() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ContactArtifactViewer_persona_button_view");
    }
    /**
     * @return <i>Persona</i>
     * @see ContactArtifactViewer
     */
    static String ContactArtifactViewer_persona_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ContactArtifactViewer_persona_header");
    }
    /**
     * @return <i>Persona </i>
     * @see ContactArtifactViewer
     */
    static String ContactArtifactViewer_persona_label() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ContactArtifactViewer_persona_label");
    }
    /**
     * @return <i>Match </i>
     * @see ContactArtifactViewer
     */
    static String ContactArtifactViewer_persona_match_num() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ContactArtifactViewer_persona_match_num");
    }
    /**
     * @return <i>No matches found</i>
     * @see ContactArtifactViewer
     */
    static String ContactArtifactViewer_persona_no_match() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ContactArtifactViewer_persona_no_match");
    }
    /**
     * @return <i>Searching...</i>
     * @see ContactArtifactViewer
     */
    static String ContactArtifactViewer_persona_searching() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ContactArtifactViewer_persona_searching");
    }
    /**
     * @return <i>Unknown</i>
     * @see ContactArtifactViewer
     */
    static String ContactArtifactViewer_persona_unknown() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ContactArtifactViewer_persona_unknown");
    }
    /**
     * @return <i>Phone</i>
     * @see ContactArtifactViewer
     */
    static String ContactArtifactViewer_phones_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ContactArtifactViewer_phones_header");
    }
    /**
     * @return <i>Failed to get some or all attributes from case database</i>
     * @see DefaultTableArtifactContentViewer
     */
    static String DataContentViewerArtifact_failedToGetAttributes_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataContentViewerArtifact.failedToGetAttributes.message");
    }
    /**
     * @return <i>Failed to get source file path from case database</i>
     * @see DefaultTableArtifactContentViewer
     */
    static String DataContentViewerArtifact_failedToGetSourcePath_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataContentViewerArtifact.failedToGetSourcePath.message");
    }
    /**
     * @return <i>Source(s)</i>
     * @see DefaultTableArtifactContentViewer
     */
    static String DefaultTableArtifactContentViewer_attrsTableHeader_sources() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DefaultTableArtifactContentViewer.attrsTableHeader.sources");
    }
    /**
     * @return <i>Type</i>
     * @see DefaultTableArtifactContentViewer
     */
    static String DefaultTableArtifactContentViewer_attrsTableHeader_type() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DefaultTableArtifactContentViewer.attrsTableHeader.type");
    }
    /**
     * @return <i>Value</i>
     * @see DefaultTableArtifactContentViewer
     */
    static String DefaultTableArtifactContentViewer_attrsTableHeader_value() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DefaultTableArtifactContentViewer.attrsTableHeader.value");
    }
    /**
     * @return <i>Created</i>
     * @see GeneralPurposeArtifactViewer
     */
    static String GeneralPurposeArtifactViewer_dates_created() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralPurposeArtifactViewer.dates.created");
    }
    /**
     * @return <i>End</i>
     * @see GeneralPurposeArtifactViewer
     */
    static String GeneralPurposeArtifactViewer_dates_end() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralPurposeArtifactViewer.dates.end");
    }
    /**
     * @return <i>Start</i>
     * @see GeneralPurposeArtifactViewer
     */
    static String GeneralPurposeArtifactViewer_dates_start() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralPurposeArtifactViewer.dates.start");
    }
    /**
     * @return <i>Time</i>
     * @see GeneralPurposeArtifactViewer
     */
    static String GeneralPurposeArtifactViewer_dates_time() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralPurposeArtifactViewer.dates.time");
    }
    /**
     * @return <i>Details</i>
     * @see GeneralPurposeArtifactViewer
     */
    static String GeneralPurposeArtifactViewer_details_attrHeader() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralPurposeArtifactViewer.details.attrHeader");
    }
    /**
     * @return <i>Bookmark Details</i>
     * @see GeneralPurposeArtifactViewer
     */
    static String GeneralPurposeArtifactViewer_details_bookmarkHeader() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralPurposeArtifactViewer.details.bookmarkHeader");
    }
    /**
     * @return <i>Cached File</i>
     * @see GeneralPurposeArtifactViewer
     */
    static String GeneralPurposeArtifactViewer_details_cachedHeader() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralPurposeArtifactViewer.details.cachedHeader");
    }
    /**
     * @return <i>Cookie Details</i>
     * @see GeneralPurposeArtifactViewer
     */
    static String GeneralPurposeArtifactViewer_details_cookieHeader() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralPurposeArtifactViewer.details.cookieHeader");
    }
    /**
     * @return <i>Data Source</i>
     * @see GeneralPurposeArtifactViewer
     */
    static String GeneralPurposeArtifactViewer_details_dataSource() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralPurposeArtifactViewer.details.dataSource");
    }
    /**
     * @return <i>Dates</i>
     * @see GeneralPurposeArtifactViewer
     */
    static String GeneralPurposeArtifactViewer_details_datesHeader() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralPurposeArtifactViewer.details.datesHeader");
    }
    /**
     * @return <i>Downloaded File</i>
     * @see GeneralPurposeArtifactViewer
     */
    static String GeneralPurposeArtifactViewer_details_downloadHeader() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralPurposeArtifactViewer.details.downloadHeader");
    }
    /**
     * @return <i>File</i>
     * @see GeneralPurposeArtifactViewer
     */
    static String GeneralPurposeArtifactViewer_details_file() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralPurposeArtifactViewer.details.file");
    }
    /**
     * @return <i>Visit Details</i>
     * @see GeneralPurposeArtifactViewer
     */
    static String GeneralPurposeArtifactViewer_details_historyHeader() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralPurposeArtifactViewer.details.historyHeader");
    }
    /**
     * @return <i>Host</i>
     * @see GeneralPurposeArtifactViewer
     */
    static String GeneralPurposeArtifactViewer_details_host() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralPurposeArtifactViewer_details_host");
    }
    /**
     * @return <i>Other</i>
     * @see GeneralPurposeArtifactViewer
     */
    static String GeneralPurposeArtifactViewer_details_otherHeader() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralPurposeArtifactViewer.details.otherHeader");
    }
    /**
     * @return <i>Web Search</i>
     * @see GeneralPurposeArtifactViewer
     */
    static String GeneralPurposeArtifactViewer_details_searchHeader() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralPurposeArtifactViewer.details.searchHeader");
    }
    /**
     * @return <i>Source</i>
     * @see GeneralPurposeArtifactViewer
     */
    static String GeneralPurposeArtifactViewer_details_sourceHeader() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralPurposeArtifactViewer.details.sourceHeader");
    }
    /**
     * @return <i>Copy</i>
     * @see GeneralPurposeArtifactViewer
     */
    static String GeneralPurposeArtifactViewer_menuitem_copy() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralPurposeArtifactViewer_menuitem_copy");
    }
    /**
     * @return <i> (no longer exists)</i>
     * @see GeneralPurposeArtifactViewer
     */
    static String GeneralPurposeArtifactViewer_noFile_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralPurposeArtifactViewer.noFile.text");
    }
    /**
     * @return <i>Term</i>
     * @see GeneralPurposeArtifactViewer
     */
    static String GeneralPurposeArtifactViewer_term_label() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralPurposeArtifactViewer.term.label");
    }
    /**
     * @return <i>Unknown</i>
     * @see GeneralPurposeArtifactViewer
     */
    static String GeneralPurposeArtifactViewer_unknown_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeneralPurposeArtifactViewer.unknown.text");
    }
    /**
     * @return <i>Account found in Message artifact</i>
     * @see MessageAccountPanel
     */
    static String MessageAccountPanel_account_justification() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MessageAccountPanel.account.justification");
    }
    /**
     * @return <i>Create</i>
     * @see MessageAccountPanel
     */
    static String MessageAccountPanel_button_create_label() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MessageAccountPanel_button_create_label");
    }
    /**
     * @return <i>View</i>
     * @see MessageAccountPanel
     */
    static String MessageAccountPanel_button_view_label() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MessageAccountPanel_button_view_label");
    }
    /**
     * @return <i>Contact:</i>
     * @see MessageAccountPanel
     */
    static String MessageAccountPanel_contact_label() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MessageAccountPanel_contact_label");
    }
    /**
     * @return <i>Copy</i>
     * @see MessageAccountPanel
     */
    static String MessageAccountPanel_copy_label() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MessageAccountPanel_copy_label");
    }
    /**
     * @param accountIdentifer accountIdentifer
     * @return <i>Unable to find an account with identifier </i>{@code accountIdentifer}<i> in the Central Repository.</i>
     * @see MessageAccountPanel
     */
    static String MessageAccountPanel_id_not_found_in_cr(Object accountIdentifer) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MessageAccountPanel_id_not_found_in_cr", accountIdentifer);
    }
    /**
     * @return <i>No matches found.</i>
     * @see MessageAccountPanel
     */
    static String MessageAccountPanel_no_matches() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MessageAccountPanel_no_matches");
    }
    /**
     * @return <i>Persona:</i>
     * @see MessageAccountPanel
     */
    static String MessageAccountPanel_persona_label() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MessageAccountPanel_persona_label");
    }
    /**
     * @return <i>Unknown</i>
     * @see MessageAccountPanel
     */
    static String MessageAccountPanel_unknown_label() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MessageAccountPanel_unknown_label");
    }
    /**
     * @return <i>Attachments</i>
     * @see MessageArtifactViewer
     */
    static String MessageArtifactViewer_AttachmentPanel_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MessageArtifactViewer.AttachmentPanel.title");
    }
    /**
     * @return <i>Account found in Call Log artifact</i>
     * @see PersonaAccountFetcher
     */
    static String PersonaAccountFetcher_account_justification() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaAccountFetcher.account.justification");
    }
    /**
     * @param accountIdentifer accountIdentifer
     * @return <i>Unable to find an account with identifier </i>{@code accountIdentifer}<i> in the Central Repository.</i>
     * @see PersonaAccountFetcher
     */
    static String PersonaAccountFetcher_not_account_in_cr(Object accountIdentifer) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaAccountFetcher_not_account_in_cr", accountIdentifer);
    }
    /**
     * @param Persona_count Persona count
     * @return <i>(1 of </i>{@code Persona_count}<i>)</i>
     * @see PersonaAccountFetcher
     */
    static String PersonaDisplayTask_persona_count_suffix(Object Persona_count) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaDisplayTask_persona_count_suffix", Persona_count);
    }
    private Bundle() {}
}
