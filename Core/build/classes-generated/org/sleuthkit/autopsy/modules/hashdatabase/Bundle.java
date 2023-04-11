package org.sleuthkit.autopsy.modules.hashdatabase;
/** Localizable strings for {@link org.sleuthkit.autopsy.modules.hashdatabase}. */
class Bundle {
    /**
     * @return <i>Error creating new hash set</i>
     * @see HashDbCreateDatabaseDialog
     */
    static String HashDbCreateDatabaseDialog_databaseCreationError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbCreateDatabaseDialog.databaseCreationError");
    }
    /**
     * @return <i>Error accessing central repository</i>
     * @see HashDbCreateDatabaseDialog
     */
    static String HashDbCreateDatabaseDialog_databaseLookupError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbCreateDatabaseDialog.databaseLookupError");
    }
    /**
     * @return <i>A hashset with this name already exists</i>
     * @see HashDbCreateDatabaseDialog
     */
    static String HashDbCreateDatabaseDialog_duplicateName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbCreateDatabaseDialog.duplicateName");
    }
    /**
     * @return <i>An organization must be selected</i>
     * @see HashDbCreateDatabaseDialog
     */
    static String HashDbCreateDatabaseDialog_missingOrg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbCreateDatabaseDialog.missingOrg");
    }
    /**
     * @return <i>Failure loading organizations.</i>
     * @see HashDbCreateDatabaseDialog
     */
    static String HashDbCreateDatabaseDialog_populateOrgsError_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbCreateDatabaseDialog.populateOrgsError.message");
    }
    /**
     * @return <i>Error accessing central repository</i>
     * @see HashDbImportDatabaseDialog
     */
    static String HashDbImportDatabaseDialog_databaseLookupError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbImportDatabaseDialog.databaseLookupError");
    }
    /**
     * @return <i>A hashset with this name and version already exists</i>
     * @see HashDbImportDatabaseDialog
     */
    static String HashDbImportDatabaseDialog_duplicateName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbImportDatabaseDialog.duplicateName");
    }
    /**
     * @return <i>An organization must be selected</i>
     * @see HashDbImportDatabaseDialog
     */
    static String HashDbImportDatabaseDialog_missingOrg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbImportDatabaseDialog.missingOrg");
    }
    /**
     * @return <i>A version must be entered</i>
     * @see HashDbImportDatabaseDialog
     */
    static String HashDbImportDatabaseDialog_missingVersion() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbImportDatabaseDialog.missingVersion");
    }
    /**
     * @return <i>A hash set name must be entered.</i>
     * @see HashDbImportDatabaseDialog
     */
    static String HashDbImportDatabaseDialog_mustEnterHashSetNameMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbImportDatabaseDialog.mustEnterHashSetNameMsg");
    }
    /**
     * @return <i>Failure loading organizations.</i>
     * @see HashDbImportDatabaseDialog
     */
    static String HashDbImportDatabaseDialog_populateOrgsError_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbImportDatabaseDialog.populateOrgsError.message");
    }
    /**
     * @return <i>No Change items found:</i>
     * @see HashDbIngestModule
     */
    static String HashDbIngestModule_complete_noChangesFound() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbIngestModule.complete.noChangesFound");
    }
    /**
     * @param File_name File name
     * @return <i>Error Finding Artifacts: </i>{@code File_name}
     * @see HashDbIngestModule
     */
    static String HashDbIngestModule_dialogTitle_errorFindingArtifacts(Object File_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbIngestModule.dialogTitle.errorFindingArtifacts", File_name);
    }
    /**
     * @param File_name File name
     * @return <i>Error encountered while looking for existing artifacts for </i>{@code File_name}<i>.</i>
     * @see HashDbIngestModule
     */
    static String HashDbIngestModule_errorMessage_lookingForFileArtifacts(Object File_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbIngestModule.errorMessage.lookingForFileArtifacts", File_name);
    }
    /**
     * @return <i>Failed to index hashset hit artifact for keyword search.</i>
     * @see HashDbIngestModule
     */
    static String HashDbIngestModule_indexError_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbIngestModule.indexError.message");
    }
    /**
     * @return <i>Notable file search will not be executed.</i>
     * @see HashDbIngestModule
     */
    static String HashDbIngestModule_knownBadFileSearchWillNotExecuteWarn() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbIngestModule.knownBadFileSearchWillNotExecuteWarn");
    }
    /**
     * @return <i>Known file search will not be executed.</i>
     * @see HashDbIngestModule
     */
    static String HashDbIngestModule_knownFileSearchWillNotExecuteWarn() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbIngestModule.knownFileSearchWillNotExecuteWarn");
    }
    /**
     * @param fileName fileName
     * @return <i>Error encountered while looking up notable hash value for </i>{@code fileName}<i>.</i>
     * @see HashDbIngestModule
     */
    static String HashDbIngestModule_lookingUpKnownBadHashValueErr(Object fileName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbIngestModule.lookingUpKnownBadHashValueErr", fileName);
    }
    /**
     * @param fileName fileName
     * @return <i>Error encountered while looking up known hash value for </i>{@code fileName}<i>.</i>
     * @see HashDbIngestModule
     */
    static String HashDbIngestModule_lookingUpKnownHashValueErr(Object fileName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbIngestModule.lookingUpKnownHashValueErr", fileName);
    }
    /**
     * @param fileName fileName
     * @return <i>Error encountered while looking up no change hash value for </i>{@code fileName}<i>.</i>
     * @see HashDbIngestModule
     */
    static String HashDbIngestModule_lookingUpNoChangeHashValueErr(Object fileName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbIngestModule.lookingUpNoChangeHashValueErr", fileName);
    }
    /**
     * @return <i>No notable hash set.</i>
     * @see HashDbIngestModule
     */
    static String HashDbIngestModule_noKnownBadHashDbSetMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbIngestModule.noKnownBadHashDbSetMsg");
    }
    /**
     * @return <i>No known hash set.</i>
     * @see HashDbIngestModule
     */
    static String HashDbIngestModule_noKnownHashDbSetMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbIngestModule.noKnownHashDbSetMsg");
    }
    /**
     * @return <i>Error loading organization</i>
     * @see HashDbManager
     */
    static String HashDbManager_CentralRepoHashDb_orgError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbManager.CentralRepoHashDb.orgError");
    }
    /**
     * @return <i>Error loading central repository hash sets</i>
     * @see HashDbManager
     */
    static String HashDbManager_centralRepoLoadError_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbManager.centralRepoLoadError.message");
    }
    /**
     * @param hashSetName hashSetName
     * @return {@code hashSetName}<i> (Custom)</i>
     * @see HashDbManager
     */
    static String HashDbManager_handleNameConflict_conflictSuffix(Object hashSetName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbManager_handleNameConflict_conflictSuffix", hashSetName);
    }
    /**
     * @return <i>Notable</i>
     * @see HashDbManager
     */
    static String HashDbManager_knownBad_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbManager.knownBad.text");
    }
    /**
     * @return <i>Known</i>
     * @see HashDbManager
     */
    static String HashDbManager_known_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbManager.known.text");
    }
    /**
     * @return <i>No Change</i>
     * @see HashDbManager
     */
    static String HashDbManager_noChange_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbManager.noChange.text");
    }
    /**
     * @param hash_set_name hash set name
     * @return <i>Couldn't get valid hash set path for: </i>{@code hash_set_name}
     * @see HashDbManager
     */
    static String HashDbManager_noDbPath_message(Object hash_set_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbManager.noDbPath.message", hash_set_name);
    }
    /**
     * @return <i>No open case available.</i>
     * @see HashDbSearchAction
     */
    static String HashDbSearchAction_noOpenCase_errMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbSearchAction.noOpenCase.errMsg");
    }
    /**
     * @return <i>No open case available.</i>
     * @see HashDbSearchPanel
     */
    static String HashDbSearchPanel_noOpenCase_errMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashDbSearchPanel.noOpenCase.errMsg");
    }
    /**
     * @return <i>Global Hash Lookup Settings</i>
     * @see HashLookupSettingsPanel
     */
    static String HashLookupSettingsPanel_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashLookupSettingsPanel.Title");
    }
    /**
     * @return <i>Central Repository</i>
     * @see HashLookupSettingsPanel
     */
    static String HashLookupSettingsPanel_centralRepo() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashLookupSettingsPanel.centralRepo");
    }
    /**
     * @return <i>Editable</i>
     * @see HashLookupSettingsPanel
     */
    static String HashLookupSettingsPanel_editable() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashLookupSettingsPanel.editable");
    }
    /**
     * @return <i>This hash set appears to be the NSRL, it will be removed from the list.<br></i>
     * @see HashLookupSettingsPanel
     */
    static String HashLookupSettingsPanel_indexNsrl_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashLookupSettingsPanel.indexNsrl.text");
    }
    /**
     * @return <i>NSRL will not be indexed</i>
     * @see HashLookupSettingsPanel
     */
    static String HashLookupSettingsPanel_indexNsrl_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashLookupSettingsPanel.indexNsrl.title");
    }
    /**
     * @return <i>N/A</i>
     * @see HashLookupSettingsPanel
     */
    static String HashLookupSettingsPanel_notApplicable() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashLookupSettingsPanel.notApplicable");
    }
    /**
     * @return <i>This will make the hash database unavailable for lookup. Do you want to proceed?<br><br>Note: The hash database can still be re-imported later.</i>
     * @see HashLookupSettingsPanel
     */
    static String HashLookupSettingsPanel_promptMessage_deleteHashDb() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashLookupSettingsPanel.promptMessage.deleteHashDb");
    }
    /**
     * @return <i>Delete Hash Database from Configuration</i>
     * @see HashLookupSettingsPanel
     */
    static String HashLookupSettingsPanel_promptTitle_deleteHashDb() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashLookupSettingsPanel.promptTitle.deleteHashDb");
    }
    /**
     * @return <i>Read only</i>
     * @see HashLookupSettingsPanel
     */
    static String HashLookupSettingsPanel_readOnly() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashLookupSettingsPanel.readOnly");
    }
    /**
     * @param hash_lookup_name hash lookup name
     * @return <i>Failed to remove hash lookup: </i>{@code hash_lookup_name}
     * @see HashLookupSettingsPanel
     */
    static String HashLookupSettingsPanel_removeDatabaseFailure_message(Object hash_lookup_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashLookupSettingsPanel.removeDatabaseFailure.message", hash_lookup_name);
    }
    /**
     * @param nsrlUrlAddress nsrlUrlAddress
     * @return <i>Instead of indexing the NSRL, please download an already indexed version available here:<br></i>{@code nsrlUrlAddress}
     * @see HashLookupSettingsPanel
     */
    static String HashLookupSettingsPanel_removeUnindexedNsrl_text(Object nsrlUrlAddress) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashLookupSettingsPanel.removeUnindexedNsrl.text", nsrlUrlAddress);
    }
    /**
     * @return <i>Unindexed NSRL(s) will be removed</i>
     * @see HashLookupSettingsPanel
     */
    static String HashLookupSettingsPanel_removeUnindexedNsrl_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashLookupSettingsPanel.removeUnindexedNsrl.title");
    }
    /**
     * @return <i>Couldn't save hash set settings.</i>
     * @see HashLookupSettingsPanel
     */
    static String HashLookupSettingsPanel_saveFail_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashLookupSettingsPanel.saveFail.message");
    }
    /**
     * @return <i>Save Fail</i>
     * @see HashLookupSettingsPanel
     */
    static String HashLookupSettingsPanel_saveFail_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashLookupSettingsPanel.saveFail.title");
    }
    /**
     * @param nsrlHashSet nsrlHashSet
     * @return <i>The following hash set appears to be an unindexed version of the NSRL, it will be removed from the list.<br>Hash set:</i>{@code nsrlHashSet}<i><br></i>
     * @see HashLookupSettingsPanel
     */
    static String HashLookupSettingsPanel_unindexedNsrl_base(Object nsrlHashSet) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashLookupSettingsPanel.unindexedNsrl.base", nsrlHashSet);
    }
    /**
     * @param nsrlHashSets nsrlHashSets
     * @return <i>The following hash sets appear to be unindexed versions of the NSRL, they will be removed from the list.<br>Hash sets:</i>{@code nsrlHashSets}<i><br></i>
     * @see HashLookupSettingsPanel
     */
    static String HashLookupSettingsPanel_unindexedNsrls_base(Object nsrlHashSets) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashLookupSettingsPanel.unindexedNsrls.base", nsrlHashSets);
    }
    /**
     * @return <i>Error reading status</i>
     * @see HashLookupSettingsPanel
     */
    static String HashLookupSettingsPanel_updateStatusError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HashLookupSettingsPanel.updateStatusError");
    }
    /**
     * @return <i>Error parsing hash set file</i>
     * @see ImportCentralRepoDbProgressDialog
     */
    static String ImportCentralRepoDbProgressDialog_errorParsingFile_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ImportCentralRepoDbProgressDialog.errorParsingFile.message");
    }
    /**
     * @return <i> hashes processed</i>
     * @see ImportCentralRepoDbProgressDialog
     */
    static String ImportCentralRepoDbProgressDialog_linesProcessed_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ImportCentralRepoDbProgressDialog.linesProcessed.message");
    }
    /**
     * @return <i>Central Repository Import Progress</i>
     * @see ImportCentralRepoDbProgressDialog
     */
    static String ImportCentralRepoDbProgressDialog_title_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ImportCentralRepoDbProgressDialog.title.text");
    }
    private Bundle() {}
}
