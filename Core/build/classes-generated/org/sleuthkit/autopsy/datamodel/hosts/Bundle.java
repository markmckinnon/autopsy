package org.sleuthkit.autopsy.datamodel.hosts;
/** Localizable strings for {@link org.sleuthkit.autopsy.datamodel.hosts}. */
class Bundle {
    /**
     * @return <i>Add Host</i>
     * @see AddEditHostDialog
     */
    static String AddEditHostDialog_addHost_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddEditHostDialog_addHost_title");
    }
    /**
     * @return <i>Edit Host</i>
     * @see AddEditHostDialog
     */
    static String AddEditHostDialog_editHost_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddEditHostDialog_editHost_title");
    }
    /**
     * @return <i>New Person...</i>
     * @see AssociateNewPersonAction
     */
    static String AssociateNewPersonAction_menuTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AssociateNewPersonAction_menuTitle");
    }
    /**
     * @param hostName hostName
     * @param personName personName
     * @return <i>There was an error while associating host </i>{@code hostName}<i> with new person </i>{@code personName}<i>.</i>
     * @see AssociateNewPersonAction
     */
    static String AssociateNewPersonAction_onError_description(Object hostName, Object personName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AssociateNewPersonAction_onError_description", hostName, personName);
    }
    /**
     * @return <i>Error While Associating New Person</i>
     * @see AssociateNewPersonAction
     */
    static String AssociateNewPersonAction_onError_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AssociateNewPersonAction_onError_title");
    }
    /**
     * @param hostName hostName
     * @param personName personName
     * @return <i>There was an error associating host </i>{@code hostName}<i> with person </i>{@code personName}<i>.</i>
     * @see AssociatePersonAction
     */
    static String AssociatePersonAction_onError_description(Object hostName, Object personName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AssociatePersonAction_onError_description", hostName, personName);
    }
    /**
     * @return <i>Error Associating Host with Person</i>
     * @see AssociatePersonAction
     */
    static String AssociatePersonAction_onError_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AssociatePersonAction_onError_title");
    }
    /**
     * @return <i>Unknown Person</i>
     * @see AssociatePersonAction
     */
    static String AssociatePersonAction_unknownPerson() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AssociatePersonAction_unknownPerson");
    }
    /**
     * @return <i>Associate with Person</i>
     * @see AssociatePersonsMenuAction
     */
    static String AssociatePersonsMenuAction_menuTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AssociatePersonsMenuAction_menuTitle");
    }
    /**
     * @return <i>Manage Hosts</i>
     * @see OpenHostsAction
     */
    static String CTL_OpenHosts() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CTL_OpenHosts");
    }
    /**
     * @return <i>Another host already has the same name.  Please choose a different name.</i>
     * @see HostNameValidator
     */
    static String HostNameValidator_getValidationMessage_onDuplicate() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HostNameValidator_getValidationMessage_onDuplicate");
    }
    /**
     * @return <i>Please provide some text for the host name.</i>
     * @see HostNameValidator
     */
    static String HostNameValidator_getValidationMessage_onEmpty() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HostNameValidator_getValidationMessage_onEmpty");
    }
    /**
     * @return <i>Please provide a new name for this host.</i>
     * @see HostNameValidator
     */
    static String HostNameValidator_getValidationMessage_sameAsOriginal() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HostNameValidator_getValidationMessage_sameAsOriginal");
    }
    /**
     * @param hostname hostname
     * @return <i>Unable to add new host </i>{@code hostname}<i> at this time.</i>
     * @see ManageHostsDialog
     */
    static String ManageHostsDialog_failureToAdd_txt(Object hostname) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageHostsDialog.failureToAdd.txt", hostname);
    }
    /**
     * @param hostname hostname
     * @return <i>Unable to delete host </i>{@code hostname}<i> at this time.</i>
     * @see ManageHostsDialog
     */
    static String ManageHostsDialog_failureToDelete_txt(Object hostname) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageHostsDialog.failureToDelete.txt", hostname);
    }
    /**
     * @param hostname hostname
     * @param hostId hostId
     * @return <i>Unable to update host </i>{@code hostname}<i> with id: </i>{@code hostId}<i> at this time.</i>
     * @see ManageHostsDialog
     */
    static String ManageHostsDialog_failureToEdit_txt(Object hostname, Object hostId) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageHostsDialog.failureToEdit.txt", hostname, hostId);
    }
    /**
     * @return <i>There was an error while fetching hosts for current case.</i>
     * @see ManageHostsDialog
     */
    static String ManageHostsDialog_failureToGetHosts_txt() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageHostsDialog.failureToGetHosts.txt");
    }
    /**
     * @return <i>  See log for more information.</i>
     * @see ManageHostsDialog
     */
    static String ManageHostsDialog_seeLog_txt() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageHostsDialog.seeLog.txt");
    }
    /**
     * @return <i>Manage Hosts</i>
     * @see ManageHostsDialog
     */
    static String ManageHostsDialog_title_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ManageHostsDialog_title_text");
    }
    /**
     * @param sourceHost sourceHost
     * @param destHost destHost
     * @return <i>Are you sure you want to merge </i>{@code sourceHost}<i> into </i>{@code destHost}<i>?<br>This may include merging OS Accounts and cannot be undone.</i>
     * @see MergeHostAction
     */
    static String MergeHostAction_confirmText(Object sourceHost, Object destHost) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MergeHostAction.confirmText", sourceHost, destHost);
    }
    /**
     * @return <i>Confirmation</i>
     * @see MergeHostAction
     */
    static String MergeHostAction_confirmTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MergeHostAction.confirmTitle");
    }
    /**
     * @return <i>An error occurred while merging hosts.<br>Try again in a few minutes or check the log for details.</i>
     * @see MergeHostAction
     */
    static String MergeHostAction_errorText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MergeHostAction.errorText");
    }
    /**
     * @return <i>Error Merging Hosts</i>
     * @see MergeHostAction
     */
    static String MergeHostAction_errorTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MergeHostAction.errorTitle");
    }
    /**
     * @param sourceHostName sourceHostName
     * @param destHostName destHostName
     * @return <i>There was an error merging host </i>{@code sourceHostName}<i> into host </i>{@code destHostName}<i>.</i>
     * @see MergeHostAction
     */
    static String MergeHostAction_onError_description(Object sourceHostName, Object destHostName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MergeHostAction_onError_description", sourceHostName, destHostName);
    }
    /**
     * @return <i>Error Merging Hosts</i>
     * @see MergeHostAction
     */
    static String MergeHostAction_onError_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MergeHostAction_onError_title");
    }
    /**
     * @return <i>Merging Hosts</i>
     * @see MergeHostAction
     */
    static String MergeHostAction_progressIndicatorName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MergeHostAction.progressIndicatorName");
    }
    /**
     * @param sourceHost sourceHost
     * @param destHost destHost
     * @return <i>Merging </i>{@code sourceHost}<i> into </i>{@code destHost}<i>...</i>
     * @see MergeHostAction
     */
    static String MergeHostAction_progressText(Object sourceHost, Object destHost) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MergeHostAction.progressText", sourceHost, destHost);
    }
    /**
     * @return <i>Merge Into Other Host</i>
     * @see MergeHostMenuAction
     */
    static String MergeHostMenuAction_menuTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MergeHostMenuAction_menuTitle");
    }
    /**
     * @return <i>Hosts</i>
     * @see OpenHostsAction
     */
    static String OpenHostsAction_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OpenHostsAction_displayName");
    }
    /**
     * @param personName personName
     * @return <i>Remove from Person (</i>{@code personName}<i>)</i>
     * @see RemoveParentPersonAction
     */
    static String RemoveParentPersonAction_menuTitle(Object personName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RemoveParentPersonAction_menuTitle", personName);
    }
    /**
     * @param hostName hostName
     * @return <i>There was an error removing person from host: </i>{@code hostName}<i>.</i>
     * @see RemoveParentPersonAction
     */
    static String RemoveParentPersonAction_onError_description(Object hostName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RemoveParentPersonAction_onError_description", hostName);
    }
    /**
     * @return <i>Error Removing Host from Person</i>
     * @see RemoveParentPersonAction
     */
    static String RemoveParentPersonAction_onError_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RemoveParentPersonAction_onError_title");
    }
    /**
     * @return <i>Unknown Person</i>
     * @see RemoveParentPersonAction
     */
    static String RemoveParentPersonAction_unknownPerson() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RemoveParentPersonAction_unknownPerson");
    }
    private Bundle() {}
}
