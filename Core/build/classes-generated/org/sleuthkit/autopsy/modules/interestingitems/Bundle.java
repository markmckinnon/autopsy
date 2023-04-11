package org.sleuthkit.autopsy.modules.interestingitems;
/** Localizable strings for {@link org.sleuthkit.autopsy.modules.interestingitems}. */
class Bundle {
    /**
     * @return <i>Not Excluded</i>
     * @see FilesSet
     */
    static String FileSet_fileIsMemberOf_noInclusiveRules_ruleName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileSet_fileIsMemberOf_noInclusiveRules_ruleName");
    }
    /**
     * @return <i>Error getting interesting files sets from settings file.</i>
     * @see FilesIdentifierIngestJobSettingsPanel
     */
    static String FilesIdentifierIngestJobSettingsPanel_getError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesIdentifierIngestJobSettingsPanel.getError");
    }
    /**
     * @return <i>Error updating interesting files sets settings file.</i>
     * @see FilesIdentifierIngestJobSettingsPanel
     */
    static String FilesIdentifierIngestJobSettingsPanel_updateError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesIdentifierIngestJobSettingsPanel.updateError");
    }
    /**
     * @return <i>Error getting interesting files sets from file.</i>
     * @see FilesIdentifierIngestModule
     */
    static String FilesIdentifierIngestModule_getFilesError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesIdentifierIngestModule.getFilesError");
    }
    /**
     * @return <i>Failed to index interesting file hit artifact for keyword search.</i>
     * @see FilesIdentifierIngestModule
     */
    static String FilesIdentifierIngestModule_indexError_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesIdentifierIngestModule.indexError.message");
    }
    /**
     * @return <i>File Filter Settings</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_Ingest_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.Ingest.Title");
    }
    /**
     * @return <i>Global Interesting Items Settings</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_Interesting_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.Interesting.Title");
    }
    /**
     * @return <i>Bytes</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_bytes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.bytes");
    }
    /**
     * @return <i>Cancel import</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_cancelImportMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.cancelImportMsg");
    }
    /**
     * @return <i>Cancel</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_cancelNewSetMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.cancelNewSetMsg");
    }
    /**
     * @param file_name file name
     * @return <i>File </i>{@code file_name}<i> exists, overwrite?</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_exportButtonActionPerformed_fileExistPrompt(Object file_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.exportButtonActionPerformed.fileExistPrompt", file_name);
    }
    /**
     * @return <i>Gigabytes</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_gigaBytes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.gigaBytes");
    }
    /**
     * @param fileName fileName
     * @param errorMessage errorMessage
     * @return <i>The rules file "</i>{@code fileName}<i>" could not be read:<br></i>{@code errorMessage}<i>.</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_importSetButtonActionPerformed_importError(Object fileName, Object errorMessage) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.importSetButtonActionPerformed.importError", fileName, errorMessage);
    }
    /**
     * @return <i>No files sets were found in the selected files.</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_importSetButtonActionPerformed_noFiles() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.importSetButtonActionPerformed.noFiles");
    }
    /**
     * @return <i>No files sets were selected.</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_importSetButtonActionPerformed_noFilesSelected() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.importSetButtonActionPerformed.noFilesSelected");
    }
    /**
     * @param filter_name filter name
     * @param profile_name profile name
     * @return <i>The selected file filter, </i>{@code filter_name}<i>, is being used by a profile, </i>{@code profile_name}<i>, and cannot be deleted while any profile uses it.</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_ingest_fileFilterInUseError(Object filter_name, Object profile_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.ingest.fileFilterInUseError", filter_name, profile_name);
    }
    /**
     * @return <i>Interesting files set exported</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_interesting_ExportedMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.interesting.ExportedMsg");
    }
    /**
     * @return <i>Copy Set</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_interesting_copySetButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.interesting.copySetButton.text");
    }
    /**
     * @return <i>Interesting Files Set Export</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_interesting_exportButtonAction_featureName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.interesting.exportButtonAction.featureName");
    }
    /**
     * @return <i>Export Set</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_interesting_exportSetButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.interesting.exportSetButton.text");
    }
    /**
     * @return <i>Export of interesting files set failed</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_interesting_failExportMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.interesting.failExportMsg");
    }
    /**
     * @return <i>Interesting files set not imported</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_interesting_failImportMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.interesting.failImportMsg");
    }
    /**
     * @return <i>Autopsy Interesting File Set File (xml)</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_interesting_fileExtensionFilterLbl() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.interesting.fileExtensionFilterLbl");
    }
    /**
     * @return <i>Interesting Files Set Import</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_interesting_importButtonAction_featureName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.interesting.importButtonAction.featureName");
    }
    /**
     * @return <i>Import Interesting files set conflict</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_interesting_importOwConflict() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.interesting.importOwConflict");
    }
    /**
     * @return <i>Import Set</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_interesting_importSetButton_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.interesting.importSetButton.text");
    }
    /**
     * @return <i>Interesting files set conflict</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_interesting_newOwConflict() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.interesting.newOwConflict");
    }
    /**
     * @param FilesSet_name FilesSet name
     * @return <i>Interesting files set "</i>{@code FilesSet_name}<i>" already exists locally, overwrite?</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_interesting_overwriteSetPrompt(Object FilesSet_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.interesting.overwriteSetPrompt", FilesSet_name);
    }
    /**
     * @param FilesSet_name FilesSet name
     * @param New_FilesSet_name New FilesSet name
     * @return <i>A standard interesting file set already exists with the name "</i>{@code FilesSet_name}<i>."  Would you like to rename your set to "</i>{@code New_FilesSet_name}<i>?"</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_interesting_standardFileConflict(Object FilesSet_name, Object New_FilesSet_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.interesting.standardFileConflict", FilesSet_name, New_FilesSet_name);
    }
    /**
     * @return <i>Kilobytes</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_kiloBytes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.kiloBytes");
    }
    /**
     * @return <i>Error loading interesting files sets from file.</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_loadError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.loadError");
    }
    /**
     * @return <i>Megabytes</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_megaBytes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.megaBytes");
    }
    /**
     * @return <i>No, skip</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_noSkipMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.noSkipMsg");
    }
    /**
     * @return <i>Error saving interesting files sets to file.</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_saveError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.saveError");
    }
    /**
     * @return <i>Yes, overwrite</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_yesOwMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.yesOwMsg");
    }
    /**
     * @return <i>Yes, create</i>
     * @see FilesSetDefsPanel
     */
    static String FilesSetDefsPanel_yesStandardFileConflictCreate() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetDefsPanel.yesStandardFileConflictCreate");
    }
    /**
     * @return <i>File Filter</i>
     * @see FilesSetPanel
     */
    static String FilesSetPanel_filter_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetPanel.filter.title");
    }
    /**
     * @return <i>Create/edit file ingest filters...</i>
     * @see FilesSetPanel
     */
    static String FilesSetPanel_ingest_createNewFilter() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetPanel.ingest.createNewFilter");
    }
    /**
     * @return <i>File ingest filters must be named.</i>
     * @see FilesSetPanel
     */
    static String FilesSetPanel_ingest_messages_filtersMustBeNamed() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetPanel.ingest.messages.filtersMustBeNamed");
    }
    /**
     * @return <i>File Filter Rule</i>
     * @see FilesSetPanel
     */
    static String FilesSetPanel_rule_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetPanel.rule.title");
    }
    /**
     * @param regex regex
     * @return <i>Warning: Comma(s) in the file extension field will be interpreted as part of a regex and will not split the entry into multiple extensions (Entered: "</i>{@code regex}<i>")</i>
     * @see FilesSetRulePanel
     */
    static String FilesSetRulePanel_CommaInRegexWarning(Object regex) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetRulePanel.CommaInRegexWarning", regex);
    }
    /**
     * @return <i>Number of days included cannot be empty.</i>
     * @see FilesSetRulePanel
     */
    static String FilesSetRulePanel_DaysIncludedEmptyError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetRulePanel.DaysIncludedEmptyError");
    }
    /**
     * @return <i>Number of days included must be a positive integer.</i>
     * @see FilesSetRulePanel
     */
    static String FilesSetRulePanel_DaysIncludedInvalidError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetRulePanel.DaysIncludedInvalidError");
    }
    /**
     * @return <i>Must have at least one condition to make a rule.</i>
     * @see FilesSetRulePanel
     */
    static String FilesSetRulePanel_NoConditionError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetRulePanel.NoConditionError");
    }
    /**
     * @return <i>Please select a valid MIME type.</i>
     * @see FilesSetRulePanel
     */
    static String FilesSetRulePanel_NoMimeTypeError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetRulePanel.NoMimeTypeError");
    }
    /**
     * @return <i>Name cannot be empty</i>
     * @see FilesSetRulePanel
     */
    static String FilesSetRulePanel_NoNameError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetRulePanel.NoNameError");
    }
    /**
     * @return <i>Path cannot be empty</i>
     * @see FilesSetRulePanel
     */
    static String FilesSetRulePanel_NoPathError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetRulePanel.NoPathError");
    }
    /**
     * @return <i>File size condition value must not be 0 (Unless = is selected).</i>
     * @see FilesSetRulePanel
     */
    static String FilesSetRulePanel_ZeroFileSizeError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetRulePanel.ZeroFileSizeError");
    }
    /**
     * @return <i>Bytes</i>
     * @see FilesSetRulePanel
     */
    static String FilesSetRulePanel_bytes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetRulePanel.bytes");
    }
    /**
     * @return <i>Gigabytes</i>
     * @see FilesSetRulePanel
     */
    static String FilesSetRulePanel_gigaBytes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetRulePanel.gigaBytes");
    }
    /**
     * @return <i>Kilobytes</i>
     * @see FilesSetRulePanel
     */
    static String FilesSetRulePanel_kiloBytes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetRulePanel.kiloBytes");
    }
    /**
     * @return <i>Megabytes</i>
     * @see FilesSetRulePanel
     */
    static String FilesSetRulePanel_megaBytes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetRulePanel.megaBytes");
    }
    /**
     * @return <i>Examples: "jpg" or "jpg,jpeg,gif"</i>
     * @see FilesSetRulePanel
     */
    static String FilesSetRulePanel_nameTextField_extensionExample() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetRulePanel.nameTextField.extensionExample");
    }
    /**
     * @return <i>Example: "file.exe"</i>
     * @see FilesSetRulePanel
     */
    static String FilesSetRulePanel_nameTextField_fullNameExample() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetRulePanel.nameTextField.fullNameExample");
    }
    /**
     * @param daysIncluded daysIncluded
     * @return <i>(modified within </i>{@code daysIncluded}<i> day(s))</i>
     * @see FilesSet
     */
    static String FilesSet_rule_dateRule_toString(Object daysIncluded) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSet.rule.dateRule.toString", daysIncluded);
    }
    /**
     * @return <i>All Files and Directories (Not Unallocated Space)</i>
     * @see FilesSetsManager
     */
    static String FilesSetsManager_allFilesAndDirectories() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetsManager.allFilesAndDirectories");
    }
    /**
     * @return <i>All Files, Directories, and Unallocated Space</i>
     * @see FilesSetsManager
     */
    static String FilesSetsManager_allFilesDirectoriesAndUnallocated() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FilesSetsManager.allFilesDirectoriesAndUnallocated");
    }
    /**
     * @param regex regex
     * @return <i>Error determining ''</i>{@code regex}<i>'' number</i>
     * @see InterestingItemsFilesSetSettings
     */
    static String InterestingItemsFilesSetSettings_readDateCondition_failedCompiledRegex(Object regex) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "InterestingItemsFilesSetSettings.readDateCondition.failedCompiledRegex", regex);
    }
    /**
     * @param condition condition
     * @param rule rule
     * @return <i>Files set is malformed for metatype condition, ''</i>{@code condition}<i>'', in rule ''</i>{@code rule}<i>''</i>
     * @see InterestingItemsFilesSetSettings
     */
    static String InterestingItemsFilesSetSettings_readMetaTypeCondition_malformedXml(Object condition, Object rule) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "InterestingItemsFilesSetSettings.readMetaTypeCondition.malformedXml", condition, rule);
    }
    /**
     * @param regex regex
     * @param rule rule
     * @return <i>Error compiling ''</i>{@code regex}<i>'' regex in rule ''</i>{@code rule}<i>''</i>
     * @see InterestingItemsFilesSetSettings
     */
    static String InterestingItemsFilesSetSettings_readNameCondition_errorCompilingRegex(Object regex, Object rule) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "InterestingItemsFilesSetSettings.readNameCondition.errorCompilingRegex", regex, rule);
    }
    /**
     * @param character character
     * @param rule rule
     * @return <i>File name has illegal character of ''</i>{@code character}<i>'' in rule ''</i>{@code rule}<i>''</i>
     * @see InterestingItemsFilesSetSettings
     */
    static String InterestingItemsFilesSetSettings_readNameCondition_illegalChar(Object character, Object rule) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "InterestingItemsFilesSetSettings.readNameCondition.illegalChar", character, rule);
    }
    /**
     * @param tagName tagName
     * @param ruleName ruleName
     * @return <i>Name condition has invalid tag name of ''</i>{@code tagName}<i>'' for rule ''</i>{@code ruleName}<i>''</i>
     * @see InterestingItemsFilesSetSettings
     */
    static String InterestingItemsFilesSetSettings_readNameCondition_invalidTag(Object tagName, Object ruleName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "InterestingItemsFilesSetSettings.readNameCondition.invalidTag", tagName, ruleName);
    }
    /**
     * @param regex regex
     * @return <i>Error compiling ''</i>{@code regex}<i>'' regex</i>
     * @see InterestingItemsFilesSetSettings
     */
    static String InterestingItemsFilesSetSettings_readPathCondition_failedCompiledRegex(Object regex) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "InterestingItemsFilesSetSettings.readPathCondition.failedCompiledRegex", regex);
    }
    /**
     * @param ruleName ruleName
     * @return <i>Error creating path condition for rule ''</i>{@code ruleName}<i>''</i>
     * @see InterestingItemsFilesSetSettings
     */
    static String InterestingItemsFilesSetSettings_readPathCondition_pathConditionCreationError(Object ruleName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "InterestingItemsFilesSetSettings.readPathCondition.pathConditionCreationError", ruleName);
    }
    /**
     * @param ruleName ruleName
     * @return <i>Invalid rule in files set, missing necessary conditions for ''</i>{@code ruleName}<i>''</i>
     * @see InterestingItemsFilesSetSettings
     */
    static String InterestingItemsFilesSetSettings_readRule_missingNecessary(Object ruleName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "InterestingItemsFilesSetSettings.readRule.missingNecessary", ruleName);
    }
    /**
     * @param filePathStr filePathStr
     * @return <i>Failed to read settings from ''</i>{@code filePathStr}<i>''</i>
     * @see InterestingItemsFilesSetSettings
     */
    static String InterestingItemsFilesSetSettings_readSerializedDefinitions_failedReadSettings(Object filePathStr) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "InterestingItemsFilesSetSettings.readSerializedDefinitions.failedReadSettings", filePathStr);
    }
    /**
     * @param rule rule
     * @return <i>Invalid comparator or size unit in files set for rule ''</i>{@code rule}<i>''</i>
     * @see InterestingItemsFilesSetSettings
     */
    static String InterestingItemsFilesSetSettings_readSizeCondition_invalidComparator(Object rule) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "InterestingItemsFilesSetSettings.readSizeCondition.invalidComparator", rule);
    }
    /**
     * @param rule rule
     * @return <i>Files set is malformed missing at least one 'fileSize' attribute for rule ''</i>{@code rule}<i>''</i>
     * @see InterestingItemsFilesSetSettings
     */
    static String InterestingItemsFilesSetSettings_readSizeCondition_malformedXml(Object rule) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "InterestingItemsFilesSetSettings.readSizeCondition.malformedXml", rule);
    }
    /**
     * @param rule rule
     * @return <i>Non integer size in files set for rule ''</i>{@code rule}<i>''</i>
     * @see InterestingItemsFilesSetSettings
     */
    static String InterestingItemsFilesSetSettings_readSizeCondition_notIntegerValue(Object rule) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "InterestingItemsFilesSetSettings.readSizeCondition.notIntegerValue", rule);
    }
    /**
     * @return <i>Error getting default interesting files settings from file.</i>
     * @see InterestingItemsIngestModuleFactory
     */
    static String InterestingItemsIngestModuleFactory_defaultSettingsError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "InterestingItemsIngestModuleFactory.defaultSettingsError");
    }
    /**
     * @param filesSetName filesSetName
     * @return {@code filesSetName}<i> (Custom)</i>
     * @see StandardInterestingFilesSetsLoader
     */
    static String StandardInterestingFileSetsLoader_customSuffixed(Object filesSetName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "StandardInterestingFileSetsLoader.customSuffixed", filesSetName);
    }
    /**
     * @return <i>Unable to properly read standard interesting files sets.</i>
     * @see StandardInterestingFilesSetsLoader
     */
    static String StandardInterestingFilesSetsLoader_cannotLoadStandard() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "StandardInterestingFilesSetsLoader_cannotLoadStandard");
    }
    /**
     * @return <i>Unable to properly read user-configured interesting files sets.</i>
     * @see StandardInterestingFilesSetsLoader
     */
    static String StandardInterestingFilesSetsLoader_cannotLoadUserConfigured() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "StandardInterestingFilesSetsLoader_cannotLoadUserConfigured");
    }
    /**
     * @return <i>Unable to write updated configuration for interesting files sets to config directory.</i>
     * @see StandardInterestingFilesSetsLoader
     */
    static String StandardInterestingFilesSetsLoader_cannotUpdateInterestingFilesSets() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "StandardInterestingFilesSetsLoader_cannotUpdateInterestingFilesSets");
    }
    private Bundle() {}
}
