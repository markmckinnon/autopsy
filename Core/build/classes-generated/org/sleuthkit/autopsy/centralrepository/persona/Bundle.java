package org.sleuthkit.autopsy.centralrepository.persona;
/** Localizable strings for {@link org.sleuthkit.autopsy.centralrepository.persona}. */
class Bundle {
    /**
     * @return <i>Metadata add failure</i>
     * @see PersonaMetadataDialog
     */
    static String AddMetadataDialog_dup_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddMetadataDialog_dup_Title");
    }
    /**
     * @return <i>A metadata entry with this name has already been added to this persona.</i>
     * @see PersonaMetadataDialog
     */
    static String AddMetadataDialog_dup_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddMetadataDialog_dup_msg");
    }
    /**
     * @return <i>Missing field(s)</i>
     * @see PersonaMetadataDialog
     */
    static String AddMetadataDialog_empty_name_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddMetadataDialog_empty_name_Title");
    }
    /**
     * @return <i>A metadata entry cannot have an empty name or value.</i>
     * @see PersonaMetadataDialog
     */
    static String AddMetadataDialog_empty_name_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddMetadataDialog_empty_name_msg");
    }
    /**
     * @return <i>Add Metadata</i>
     * @see PersonaMetadataDialog
     */
    static String AddMetadataDialog_title_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddMetadataDialog.title.text");
    }
    /**
     * @return <i>Failed to create account.</i>
     * @see CreatePersonaAccountDialog
     */
    static String CreatePersonaAccountDialog_error_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CreatePersonaAccountDialog_error_msg");
    }
    /**
     * @return <i>Account failure</i>
     * @see CreatePersonaAccountDialog
     */
    static String CreatePersonaAccountDialog_error_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CreatePersonaAccountDialog_error_title");
    }
    /**
     * @return <i>Invalid account identifier</i>
     * @see CreatePersonaAccountDialog
     */
    static String CreatePersonaAccountDialog_invalid_account_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CreatePersonaAccountDialog_invalid_account_Title");
    }
    /**
     * @return <i>Account identifier is not valid.</i>
     * @see CreatePersonaAccountDialog
     */
    static String CreatePersonaAccountDialog_invalid_account_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CreatePersonaAccountDialog_invalid_account_msg");
    }
    /**
     * @return <i>Account added.</i>
     * @see CreatePersonaAccountDialog
     */
    static String CreatePersonaAccountDialog_success_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CreatePersonaAccountDialog_success_msg");
    }
    /**
     * @return <i>Account added</i>
     * @see CreatePersonaAccountDialog
     */
    static String CreatePersonaAccountDialog_success_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CreatePersonaAccountDialog_success_title");
    }
    /**
     * @return <i>Create Account</i>
     * @see CreatePersonaAccountDialog
     */
    static String CreatePersonaAccountDialog_title_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CreatePersonaAccountDialog.title.text");
    }
    /**
     * @return <i>Personas</i>
     * @see OpenPersonasAction
     */
    static String OpenPersonasAction_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OpenPersonasAction.displayName");
    }
    /**
     * @return <i>Account add failure</i>
     * @see PersonaAccountDialog
     */
    static String PersonaAccountDialog_dup_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaAccountDialog_dup_Title");
    }
    /**
     * @return <i>This account is already added to the persona.</i>
     * @see PersonaAccountDialog
     */
    static String PersonaAccountDialog_dup_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaAccountDialog_dup_msg");
    }
    /**
     * @return <i>Central Repository failure</i>
     * @see PersonaAccountDialog
     */
    static String PersonaAccountDialog_get_types_exception_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaAccountDialog_get_types_exception_Title");
    }
    /**
     * @return <i>Failed to access central repository.</i>
     * @see PersonaAccountDialog
     */
    static String PersonaAccountDialog_get_types_exception_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaAccountDialog_get_types_exception_msg");
    }
    /**
     * @return <i>Empty identifier</i>
     * @see PersonaAccountDialog
     */
    static String PersonaAccountDialog_identifier_empty_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaAccountDialog_identifier_empty_Title");
    }
    /**
     * @return <i>The identifier field cannot be empty.</i>
     * @see PersonaAccountDialog
     */
    static String PersonaAccountDialog_identifier_empty_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaAccountDialog_identifier_empty_msg");
    }
    /**
     * @return <i>Invalid account identifier</i>
     * @see PersonaAccountDialog
     */
    static String PersonaAccountDialog_invalid_account_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaAccountDialog_invalid_account_Title");
    }
    /**
     * @return <i>Account identifier is not valid.</i>
     * @see PersonaAccountDialog
     */
    static String PersonaAccountDialog_invalid_account_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaAccountDialog_invalid_account_msg");
    }
    /**
     * @return <i>Account not found</i>
     * @see PersonaAccountDialog
     */
    static String PersonaAccountDialog_search_empty_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaAccountDialog_search_empty_Title");
    }
    /**
     * @return <i>Account not found for given identifier and type.</i>
     * @see PersonaAccountDialog
     */
    static String PersonaAccountDialog_search_empty_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaAccountDialog_search_empty_msg");
    }
    /**
     * @return <i>Account add failure</i>
     * @see PersonaAccountDialog
     */
    static String PersonaAccountDialog_search_failure_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaAccountDialog_search_failure_Title");
    }
    /**
     * @return <i>Central Repository account search failed.</i>
     * @see PersonaAccountDialog
     */
    static String PersonaAccountDialog_search_failure_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaAccountDialog_search_failure_msg");
    }
    /**
     * @return <i>Add Account</i>
     * @see PersonaAccountDialog
     */
    static String PersonaAccountDialog_title_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaAccountDialog.title.text");
    }
    /**
     * @return <i>Alias add failure</i>
     * @see PersonaAliasDialog
     */
    static String PersonaAliasDialog_dup_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaAliasDialog_dup_Title");
    }
    /**
     * @return <i>This alias has already been added to this persona.</i>
     * @see PersonaAliasDialog
     */
    static String PersonaAliasDialog_dup_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaAliasDialog_dup_msg");
    }
    /**
     * @return <i>Empty alias</i>
     * @see PersonaAliasDialog
     */
    static String PersonaAliasDialog_empty_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaAliasDialog_empty_Title");
    }
    /**
     * @return <i>An alias cannot be empty.</i>
     * @see PersonaAliasDialog
     */
    static String PersonaAliasDialog_empty_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaAliasDialog_empty_msg");
    }
    /**
     * @return <i>Add Alias</i>
     * @see PersonaAliasDialog
     */
    static String PersonaAliasDialog_title_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaAliasDialog.title.text");
    }
    /**
     * @return <i>Create Persona</i>
     * @see PersonaDetailsDialog
     */
    static String PersonaDetailsDialogCreateTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaDetailsDialogCreateTitle");
    }
    /**
     * @return <i>Edit Persona</i>
     * @see PersonaDetailsDialog
     */
    static String PersonaDetailsDialogEditTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaDetailsDialogEditTitle");
    }
    /**
     * @return <i>View Persona</i>
     * @see PersonaDetailsDialog
     */
    static String PersonaDetailsDialogViewTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaDetailsDialogViewTitle");
    }
    /**
     * @return <i>Central Repository failure</i>
     * @see PersonaDetailsPanel
     */
    static String PersonaDetailsPanel_CentralRepoErr_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaDetailsPanel_CentralRepoErr_Title");
    }
    /**
     * @return <i>Failure to write to Central Repository.</i>
     * @see PersonaDetailsPanel
     */
    static String PersonaDetailsPanel_CentralRepoErr_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaDetailsPanel_CentralRepoErr_msg");
    }
    /**
     * @return <i>Empty persona comment</i>
     * @see PersonaDetailsPanel
     */
    static String PersonaDetailsPanel_EmptyComment_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaDetailsPanel_EmptyComment_Title");
    }
    /**
     * @return <i>Persona comment cannot be empty.</i>
     * @see PersonaDetailsPanel
     */
    static String PersonaDetailsPanel_EmptyComment_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaDetailsPanel_EmptyComment_msg");
    }
    /**
     * @return <i>Empty persona name</i>
     * @see PersonaDetailsPanel
     */
    static String PersonaDetailsPanel_EmptyName_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaDetailsPanel_EmptyName_Title");
    }
    /**
     * @return <i>Persona name cannot be empty.</i>
     * @see PersonaDetailsPanel
     */
    static String PersonaDetailsPanel_EmptyName_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaDetailsPanel_EmptyName_msg");
    }
    /**
     * @return <i>Missing account</i>
     * @see PersonaDetailsPanel
     */
    static String PersonaDetailsPanel_NotEnoughAccounts_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaDetailsPanel_NotEnoughAccounts_Title");
    }
    /**
     * @return <i>A persona needs at least one account.</i>
     * @see PersonaDetailsPanel
     */
    static String PersonaDetailsPanel_NotEnoughAccounts_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaDetailsPanel_NotEnoughAccounts_msg");
    }
    /**
     * @return <i>Empty justification</i>
     * @see PersonaDetailsPanel
     */
    static String PersonaDetailsPanel_empty_justification_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaDetailsPanel_empty_justification_Title");
    }
    /**
     * @return <i>The justification field cannot be empty</i>
     * @see PersonaDetailsPanel
     */
    static String PersonaDetailsPanel_empty_justification_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaDetailsPanel_empty_justification_msg");
    }
    /**
     * @return <i>Initialization failure</i>
     * @see PersonaDetailsPanel
     */
    static String PersonaDetailsPanel_load_exception_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaDetailsPanel_load_exception_Title");
    }
    /**
     * @return <i>Failed to load persona.</i>
     * @see PersonaDetailsPanel
     */
    static String PersonaDetailsPanel_load_exception_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonaDetailsPanel_load_exception_msg");
    }
    /**
     * @return <i>Personas</i>
     * @see PersonasTopComponent
     */
    static String PersonasTopComponent_Name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonasTopComponent_Name");
    }
    /**
     * @return <i>Are you sure?</i>
     * @see PersonasTopComponent
     */
    static String PersonasTopComponent_delete_confirmation_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonasTopComponent_delete_confirmation_Title");
    }
    /**
     * @return <i>Are you sure you want to delete this persona?</i>
     * @see PersonasTopComponent
     */
    static String PersonasTopComponent_delete_confirmation_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonasTopComponent_delete_confirmation_msg");
    }
    /**
     * @return <i>Delete failure</i>
     * @see PersonasTopComponent
     */
    static String PersonasTopComponent_delete_exception_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonasTopComponent_delete_exception_Title");
    }
    /**
     * @return <i>Failed to delete persona.</i>
     * @see PersonasTopComponent
     */
    static String PersonasTopComponent_delete_exception_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonasTopComponent_delete_exception_msg");
    }
    /**
     * @return <i>Central Repository is not enabled.</i>
     * @see PersonasTopComponent
     */
    static String PersonasTopComponent_noCR_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonasTopComponent_noCR_msg");
    }
    /**
     * @return <i>There was a failure during the search.  Try opening a case to fully initialize the central repository database.</i>
     * @see PersonasTopComponent
     */
    static String PersonasTopComponent_search_exception_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonasTopComponent_search_exception_Title");
    }
    /**
     * @return <i>Failed to search personas.</i>
     * @see PersonasTopComponent
     */
    static String PersonasTopComponent_search_exception_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonasTopComponent_search_exception_msg");
    }
    private Bundle() {}
}
