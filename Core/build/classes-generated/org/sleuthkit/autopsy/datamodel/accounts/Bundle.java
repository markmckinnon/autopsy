package org.sleuthkit.autopsy.datamodel.accounts;
/** Localizable strings for {@link org.sleuthkit.autopsy.datamodel.accounts}. */
class Bundle {
    /**
     * @return <i>Accounts</i>
     * @see Accounts
     */
    static String AccountsRootNode_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AccountsRootNode.name");
    }
    /**
     * @return <i>Accounts</i>
     * @see Accounts
     */
    static String Accounts_BINNode_accountsProperty_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Accounts.BINNode.accountsProperty.displayName");
    }
    /**
     * @return <i>Bank City</i>
     * @see Accounts
     */
    static String Accounts_BINNode_bankCityProperty_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Accounts.BINNode.bankCityProperty.displayName");
    }
    /**
     * @return <i>Bank Country</i>
     * @see Accounts
     */
    static String Accounts_BINNode_bankCountryProperty_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Accounts.BINNode.bankCountryProperty.displayName");
    }
    /**
     * @return <i>Bank Phone #</i>
     * @see Accounts
     */
    static String Accounts_BINNode_bankPhoneProperty_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Accounts.BINNode.bankPhoneProperty.displayName");
    }
    /**
     * @return <i>Bank</i>
     * @see Accounts
     */
    static String Accounts_BINNode_bankProperty_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Accounts.BINNode.bankProperty.displayName");
    }
    /**
     * @return <i>Bank URL</i>
     * @see Accounts
     */
    static String Accounts_BINNode_bankURLProperty_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Accounts.BINNode.bankURLProperty.displayName");
    }
    /**
     * @return <i>Bank Identifier Number</i>
     * @see Accounts
     */
    static String Accounts_BINNode_binProperty_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Accounts.BINNode.binProperty.displayName");
    }
    /**
     * @return <i>Brand</i>
     * @see Accounts
     */
    static String Accounts_BINNode_brandProperty_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Accounts.BINNode.brandProperty.displayName");
    }
    /**
     * @return <i>Payment Card Type</i>
     * @see Accounts
     */
    static String Accounts_BINNode_cardTypeProperty_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Accounts.BINNode.cardTypeProperty.displayName");
    }
    /**
     * @return <i>no description</i>
     * @see Accounts
     */
    static String Accounts_BINNode_noDescription() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Accounts.BINNode.noDescription");
    }
    /**
     * @return <i>Credit Card Scheme</i>
     * @see Accounts
     */
    static String Accounts_BINNode_schemeProperty_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Accounts.BINNode.schemeProperty.displayName");
    }
    /**
     * @param number_of_children number of children
     * @return <i>By BIN (</i>{@code number_of_children}<i>)</i>
     * @see Accounts
     */
    static String Accounts_ByBINNode_displayName(Object number_of_children) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Accounts.ByBINNode.displayName", number_of_children);
    }
    /**
     * @return <i>By BIN</i>
     * @see Accounts
     */
    static String Accounts_ByBINNode_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Accounts.ByBINNode.name");
    }
    /**
     * @param number_of_children number of children
     * @return <i>By File (</i>{@code number_of_children}<i>)</i>
     * @see Accounts
     */
    static String Accounts_ByFileNode_displayName(Object number_of_children) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Accounts.ByFileNode.displayName", number_of_children);
    }
    /**
     * @return <i>Accounts</i>
     * @see Accounts
     */
    static String Accounts_FileWithCCNNode_accountsProperty_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Accounts.FileWithCCNNode.accountsProperty.displayName");
    }
    /**
     * @return <i>File</i>
     * @see Accounts
     */
    static String Accounts_FileWithCCNNode_nameProperty_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Accounts.FileWithCCNNode.nameProperty.displayName");
    }
    /**
     * @return <i>no description</i>
     * @see Accounts
     */
    static String Accounts_FileWithCCNNode_noDescription() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Accounts.FileWithCCNNode.noDescription");
    }
    /**
     * @return <i>Status</i>
     * @see Accounts
     */
    static String Accounts_FileWithCCNNode_statusProperty_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Accounts.FileWithCCNNode.statusProperty.displayName");
    }
    /**
     * @param raw_file_name raw file name
     * @param solr_chunk_id solr chunk id
     * @return {@code raw_file_name}<i>_chunk_</i>{@code solr_chunk_id}
     * @see Accounts
     */
    static String Accounts_FileWithCCNNode_unallocatedSpaceFile_displayName(Object raw_file_name, Object solr_chunk_id) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Accounts.FileWithCCNNode.unallocatedSpaceFile.displayName", raw_file_name, solr_chunk_id);
    }
    /**
     * @return <i>Communication Accounts</i>
     * @see Accounts
     */
    static String Accounts_RootNode_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Accounts.RootNode.displayName");
    }
    /**
     * @return <i>Approve Accounts</i>
     * @see Accounts
     */
    static String ApproveAccountsAction_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ApproveAccountsAction.name");
    }
    /**
     * @return <i>Reject Accounts</i>
     * @see Accounts
     */
    static String RejectAccountsAction_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejectAccountsAction.name");
    }
    /**
     * @return <i>Show Rejected Results</i>
     * @see Accounts
     */
    static String ToggleShowRejected_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ToggleShowRejected.name");
    }
    private Bundle() {}
}
