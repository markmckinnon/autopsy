package org.sleuthkit.autopsy.logicalimager.configuration;
/** Localizable strings for {@link org.sleuthkit.autopsy.logicalimager.configuration}. */
class Bundle {
    /**
     * @return <i>Create Logical Imager</i>
     * @see CreateLogicalImagerAction
     */
    static String CTL_CreateLogicalImagerAction() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CTL_CreateLogicalImagerAction");
    }
    /**
     * @return <i>Select a Logical Imager configuration</i>
     * @see ConfigVisualPanel1
     */
    static String ConfigVisualPanel1_chooseFileTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel1.chooseFileTitle");
    }
    /**
     * @param filename filename
     * @return <i>Configuration file </i>{@code filename}<i> is empty</i>
     * @see ConfigVisualPanel1
     */
    static String ConfigVisualPanel1_configFileIsEmpty(Object filename) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel1.configFileIsEmpty", filename);
    }
    /**
     * @return <i>Configuration error</i>
     * @see ConfigVisualPanel1
     */
    static String ConfigVisualPanel1_configurationError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel1.configurationError");
    }
    /**
     * @param root root
     * @param description description
     * @param size_with_unit size with unit
     * @param file_system file system
     * @return {@code root}<i> (</i>{@code description}<i>) (</i>{@code size_with_unit}<i>) - File system: </i>{@code file_system}
     * @see ConfigVisualPanel1
     */
    static String ConfigVisualPanel1_driveListItem(Object root, Object description, Object size_with_unit, Object file_system) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel1.driveListItem", root, description, size_with_unit, file_system);
    }
    /**
     * @return <i>Configuration JSON File</i>
     * @see ConfigVisualPanel1
     */
    static String ConfigVisualPanel1_fileNameExtensionFilter() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel1.fileNameExtensionFilter");
    }
    /**
     * @return <i>Invalid config JSON: </i>
     * @see ConfigVisualPanel1
     */
    static String ConfigVisualPanel1_invalidConfigJson() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel1.invalidConfigJson");
    }
    /**
     * @return <i>No drive found</i>
     * @see ConfigVisualPanel1
     */
    static String ConfigVisualPanel1_messageLabel_noExternalDriveFound() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel1.messageLabel.noExternalDriveFound");
    }
    /**
     * @return <i>Select location</i>
     * @see ConfigVisualPanel1
     */
    static String ConfigVisualPanel1_selectConfigurationFile() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel1.selectConfigurationFile");
    }
    /**
     * @return <i>Unknown</i>
     * @see ConfigVisualPanel1
     */
    static String ConfigVisualPanel1_unknown() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel1.unknown");
    }
    /**
     * @return <i>Cancel</i>
     * @see ConfigVisualPanel2
     */
    static String ConfigVisualPanel2_cancel() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel2.cancel");
    }
    /**
     * @return <i>Delete rule </i>
     * @see ConfigVisualPanel2
     */
    static String ConfigVisualPanel2_deleteRuleSet() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel2.deleteRuleSet");
    }
    /**
     * @return <i>Delete rule confirmation</i>
     * @see ConfigVisualPanel2
     */
    static String ConfigVisualPanel2_deleteRuleSetConfirmation() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel2.deleteRuleSetConfirmation");
    }
    /**
     * @return <i>Configure imager</i>
     * @see ConfigVisualPanel2
     */
    static String ConfigVisualPanel2_editConfiguration() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel2.editConfiguration");
    }
    /**
     * @return <i>Edit rule error</i>
     * @see ConfigVisualPanel2
     */
    static String ConfigVisualPanel2_editRuleError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel2.editRuleError");
    }
    /**
     * @return <i>Edit Rule</i>
     * @see ConfigVisualPanel2
     */
    static String ConfigVisualPanel2_editRuleSet() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel2.editRuleSet");
    }
    /**
     * @param ruleName ruleName
     * @return <i>A rule with name "</i>{@code ruleName}<i>" already exists. Please enter a different rule name</i>
     * @see ConfigVisualPanel2
     */
    static String ConfigVisualPanel2_newRuleError_duplicateName(Object ruleName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel2.newRuleError.duplicateName", ruleName);
    }
    /**
     * @return <i>New rule error</i>
     * @see ConfigVisualPanel2
     */
    static String ConfigVisualPanel2_newRuleError_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel2.newRuleError.title");
    }
    /**
     * @return <i>New Rule</i>
     * @see ConfigVisualPanel2
     */
    static String ConfigVisualPanel2_newRule_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel2.newRule.name");
    }
    /**
     * @return <i>OK</i>
     * @see ConfigVisualPanel2
     */
    static String ConfigVisualPanel2_ok() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel2.ok");
    }
    /**
     * @return <i>Rule Name</i>
     * @see ConfigVisualPanel2
     */
    static String ConfigVisualPanel2_rulesTable_columnModel_title0() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel2.rulesTable.columnModel.title0");
    }
    /**
     * @return <i>Description</i>
     * @see ConfigVisualPanel2
     */
    static String ConfigVisualPanel2_rulesTable_columnModel_title1() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel2.rulesTable.columnModel.title1");
    }
    /**
     * @return <i>Unable to save file</i>
     * @see ConfigVisualPanel3
     */
    static String ConfigVisualPanel3_copyStatus_error() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel3.copyStatus.error");
    }
    /**
     * @return <i>File has not been saved</i>
     * @see ConfigVisualPanel3
     */
    static String ConfigVisualPanel3_copyStatus_notSaved() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel3.copyStatus.notSaved");
    }
    /**
     * @return <i>Saved</i>
     * @see ConfigVisualPanel3
     */
    static String ConfigVisualPanel3_copyStatus_saved() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel3.copyStatus.saved");
    }
    /**
     * @return <i>Saving file, please wait</i>
     * @see ConfigVisualPanel3
     */
    static String ConfigVisualPanel3_copyStatus_savingInProgress() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel3.copyStatus.savingInProgress");
    }
    /**
     * @param configurationLocation configurationLocation
     * @return <i>Press Save to write the imaging tool and configuration file to the destination.<br>Destination: </i>{@code configurationLocation}
     * @see ConfigVisualPanel3
     */
    static String ConfigVisualPanel3_description_text(Object configurationLocation) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel3.description.text", configurationLocation);
    }
    /**
     * @return <i>Cannot locate logical imager, cannot copy to destination</i>
     * @see ConfigVisualPanel3
     */
    static String ConfigVisualPanel3_errorMsg_cannotFindLogicalImager() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel3.errorMsg.cannotFindLogicalImager");
    }
    /**
     * @param configFilename configFilename
     * @return <i>Failed to save configuration file: </i>{@code configFilename}
     * @see ConfigVisualPanel3
     */
    static String ConfigVisualPanel3_failedToSaveConfigMsg(Object configFilename) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel3.failedToSaveConfigMsg", configFilename);
    }
    /**
     * @return <i>Failed to save tsk_logical_imager.exe file</i>
     * @see ConfigVisualPanel3
     */
    static String ConfigVisualPanel3_failedToSaveExeMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel3.failedToSaveExeMsg");
    }
    /**
     * @param reason reason
     * @return <i><br>Reason: </i>{@code reason}
     * @see ConfigVisualPanel3
     */
    static String ConfigVisualPanel3_reason(Object reason) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel3.reason", reason);
    }
    /**
     * @return <i>Save imager</i>
     * @see ConfigVisualPanel3
     */
    static String ConfigVisualPanel3_saveConfigurationFile() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ConfigVisualPanel3.saveConfigurationFile");
    }
    /**
     * @return <i>Create Logical Imager</i>
     * @see CreateLogicalImagerAction
     */
    static String CreateLogicalImagerAction_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CreateLogicalImagerAction.title");
    }
    /**
     * @return <i>Example: </i>
     * @see EditFullPathsRulePanel
     */
    static String EditFullPathsRulePanel_example() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditFullPathsRulePanel.example");
    }
    /**
     * @return <i>Full paths</i>
     * @see EditFullPathsRulePanel
     */
    static String EditFullPathsRulePanel_fullPaths() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditFullPathsRulePanel.fullPaths");
    }
    /**
     * @return <i>Extensions cannot have an empty entry</i>
     * @see EditNonFullPathsRulePanel
     */
    static String EditNonFullPathsRulePanel_emptyExtensionException() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditNonFullPathsRulePanel.emptyExtensionException");
    }
    /**
     * @return <i>Example: </i>
     * @see EditNonFullPathsRulePanel
     */
    static String EditNonFullPathsRulePanel_example() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditNonFullPathsRulePanel.example");
    }
    /**
     * @return <i>File names</i>
     * @see EditNonFullPathsRulePanel
     */
    static String EditNonFullPathsRulePanel_fileNames() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditNonFullPathsRulePanel.fileNames");
    }
    /**
     * @return <i>Folder names</i>
     * @see EditNonFullPathsRulePanel
     */
    static String EditNonFullPathsRulePanel_folderNames() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditNonFullPathsRulePanel.folderNames");
    }
    /**
     * @param message message
     * @return <i>Maximum file size must be a number: </i>{@code message}
     * @see EditNonFullPathsRulePanel
     */
    static String EditNonFullPathsRulePanel_maxFileSizeMustBeNumberException(Object message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditNonFullPathsRulePanel.maxFileSizeMustBeNumberException", message);
    }
    /**
     * @return <i>Maximum file size must be a positive</i>
     * @see EditNonFullPathsRulePanel
     */
    static String EditNonFullPathsRulePanel_maxFileSizeNotPositiveException() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditNonFullPathsRulePanel.maxFileSizeNotPositiveException");
    }
    /**
     * @param maxFileSize maxFileSize
     * @param minFileSize minFileSize
     * @return <i>Maximum file size: </i>{@code maxFileSize}<i> bytes must be bigger than minimum file size: </i>{@code minFileSize}<i> bytes</i>
     * @see EditNonFullPathsRulePanel
     */
    static String EditNonFullPathsRulePanel_maxFileSizeSmallerThanMinException(Object maxFileSize, Object minFileSize) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditNonFullPathsRulePanel.maxFileSizeSmallerThanMinException", maxFileSize, minFileSize);
    }
    /**
     * @param message message
     * @return <i>Minimum file size must be a number: </i>{@code message}
     * @see EditNonFullPathsRulePanel
     */
    static String EditNonFullPathsRulePanel_minFileSizeMustBeNumberException(Object message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditNonFullPathsRulePanel.minFileSizeMustBeNumberException", message);
    }
    /**
     * @return <i>Minimum file size must be a positive</i>
     * @see EditNonFullPathsRulePanel
     */
    static String EditNonFullPathsRulePanel_minFileSizeNotPositiveException() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditNonFullPathsRulePanel.minFileSizeNotPositiveException");
    }
    /**
     * @param message message
     * @return <i>Modified days must be a number: </i>{@code message}
     * @see EditNonFullPathsRulePanel
     */
    static String EditNonFullPathsRulePanel_modifiedDaysMustBeNumberException(Object message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditNonFullPathsRulePanel.modifiedDaysMustBeNumberException", message);
    }
    /**
     * @return <i>Modified days must be a positive</i>
     * @see EditNonFullPathsRulePanel
     */
    static String EditNonFullPathsRulePanel_modifiedDaysNotPositiveException() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditNonFullPathsRulePanel.modifiedDaysNotPositiveException");
    }
    /**
     * @return <i>Bytes</i>
     * @see EditNonFullPathsRulePanel
     */
    static String EditNonFullPathsRulePanel_units_bytes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditNonFullPathsRulePanel.units.bytes");
    }
    /**
     * @return <i>Gigabytes</i>
     * @see EditNonFullPathsRulePanel
     */
    static String EditNonFullPathsRulePanel_units_gigabytes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditNonFullPathsRulePanel.units.gigabytes");
    }
    /**
     * @return <i>Kilobytes</i>
     * @see EditNonFullPathsRulePanel
     */
    static String EditNonFullPathsRulePanel_units_kilobytes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditNonFullPathsRulePanel.units.kilobytes");
    }
    /**
     * @return <i>Megabytes</i>
     * @see EditNonFullPathsRulePanel
     */
    static String EditNonFullPathsRulePanel_units_megabytes() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditNonFullPathsRulePanel.units.megabytes");
    }
    /**
     * @param fieldName fieldName
     * @return {@code fieldName}<i> cannot have a blank line</i>
     * @see EditRulePanel
     */
    static String EditRulePanel_blankLineException(Object fieldName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditRulePanel.blankLineException", fieldName);
    }
    /**
     * @return <i>Rule name cannot be empty</i>
     * @see EditRulePanel
     */
    static String EditRulePanel_emptyRuleName_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditRulePanel.emptyRuleName.message");
    }
    /**
     * @param ruleName ruleName
     * @return <i>Rule name "</i>{@code ruleName}<i>" is reserved for use with a predefined rule</i>
     * @see EditRulePanel
     */
    static String EditRulePanel_reservedRuleName_message(Object ruleName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditRulePanel.reservedRuleName.message", ruleName);
    }
    /**
     * @return <i>Find encryption programs</i>
     * @see EncryptionProgramsRule
     */
    static String EncryptionProgramsRule_encryptionProgramsRuleDescription() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EncryptionProgramsRule.encryptionProgramsRuleDescription");
    }
    /**
     * @return <i>Encryption Programs</i>
     * @see EncryptionProgramsRule
     */
    static String EncryptionProgramsRule_encryptionProgramsRuleName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EncryptionProgramsRule.encryptionProgramsRuleName");
    }
    /**
     * @return <i>A rule with full-paths cannot have other rule definitions</i>
     * @see LogicalImagerConfigDeserializer
     */
    static String LogicalImagerConfigDeserializer_fullPathsException() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalImagerConfigDeserializer.fullPathsException");
    }
    /**
     * @return <i>Missing rule-set</i>
     * @see LogicalImagerConfigDeserializer
     */
    static String LogicalImagerConfigDeserializer_missingRuleSetException() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalImagerConfigDeserializer.missingRuleSetException");
    }
    /**
     * @param key key
     * @return <i>Unsupported key: </i>{@code key}
     * @see LogicalImagerConfigDeserializer
     */
    static String LogicalImagerConfigDeserializer_unsupportedKeyException(Object key) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LogicalImagerConfigDeserializer.unsupportedKeyException", key);
    }
    /**
     * @return <i>Search for files based on one or more attributes or metadata fields.</i>
     * @see NewRulePanel
     */
    static String NewRuleSetPanel_attributeRule_description() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "NewRuleSetPanel.attributeRule.description");
    }
    /**
     * @return <i>Attribute</i>
     * @see NewRulePanel
     */
    static String NewRuleSetPanel_attributeRule_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "NewRuleSetPanel.attributeRule.name");
    }
    /**
     * @return <i>Search for files based on full exact match path.</i>
     * @see NewRulePanel
     */
    static String NewRuleSetPanel_fullPathRule_description() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "NewRuleSetPanel.fullPathRule.description");
    }
    /**
     * @return <i>Full Path</i>
     * @see NewRulePanel
     */
    static String NewRuleSetPanel_fullPathRule_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "NewRuleSetPanel.fullPathRule.name");
    }
    private Bundle() {}
}
