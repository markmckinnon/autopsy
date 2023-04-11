package org.sleuthkit.autopsy.texttranslation.translators;
/** Localizable strings for {@link org.sleuthkit.autopsy.texttranslation.translators}. */
class Bundle {
    /**
     * @return <i>Invalid translation authentication key</i>
     * @see BingTranslatorSettingsPanel
     */
    static String BingTranslatorSettingsPanel_warning_invalidKey() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "BingTranslatorSettingsPanel.warning.invalidKey");
    }
    /**
     * @return <i>Unable to get list of target languages or parse the result that was received</i>
     * @see BingTranslatorSettingsPanel
     */
    static String BingTranslatorSettingsPanel_warning_targetLanguageFailure() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "BingTranslatorSettingsPanel.warning.targetLanguageFailure");
    }
    /**
     * @return <i>Bing Translator</i>
     * @see BingTranslator
     */
    static String BingTranslator_name_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "BingTranslator.name.text");
    }
    /**
     * @return <i>Credentials file not found, please set the location to be a valid JSON credentials file.</i>
     * @see GoogleTranslatorSettingsPanel
     */
    static String GoogleTranslatorSettingsPanel_errorMessage_fileNotFound() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GoogleTranslatorSettingsPanel.errorMessage.fileNotFound");
    }
    /**
     * @return <i>A JSON file must be selected to provide your credentials for Google Translate.</i>
     * @see GoogleTranslatorSettingsPanel
     */
    static String GoogleTranslatorSettingsPanel_errorMessage_noFileSelected() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GoogleTranslatorSettingsPanel.errorMessage.noFileSelected");
    }
    /**
     * @return <i>Translation failure with specified credentials</i>
     * @see GoogleTranslatorSettingsPanel
     */
    static String GoogleTranslatorSettingsPanel_errorMessage_translationFailure() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GoogleTranslatorSettingsPanel.errorMessage.translationFailure");
    }
    /**
     * @return <i>Unable to construct credentials object from credentials file, please set the location to be a valid JSON credentials file.</i>
     * @see GoogleTranslatorSettingsPanel
     */
    static String GoogleTranslatorSettingsPanel_errorMessage_unableToMakeCredentials() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GoogleTranslatorSettingsPanel.errorMessage.unableToMakeCredentials");
    }
    /**
     * @return <i>Unable to read credentials from credentials file, please set the location to be a valid JSON credentials file.</i>
     * @see GoogleTranslatorSettingsPanel
     */
    static String GoogleTranslatorSettingsPanel_errorMessage_unableToReadCredentials() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GoogleTranslatorSettingsPanel.errorMessage.unableToReadCredentials");
    }
    /**
     * @return <i>Failure getting list of supported languages with current credentials file.</i>
     * @see GoogleTranslatorSettingsPanel
     */
    static String GoogleTranslatorSettingsPanel_errorMessage_unknownFailureGetting() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GoogleTranslatorSettingsPanel.errorMessage.unknownFailureGetting");
    }
    /**
     * @return <i>Failure populating list of supported languages with current credentials file.</i>
     * @see GoogleTranslatorSettingsPanel
     */
    static String GoogleTranslatorSettingsPanel_errorMessage_unknownFailurePopulating() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GoogleTranslatorSettingsPanel.errorMessage.unknownFailurePopulating");
    }
    /**
     * @return <i>Select</i>
     * @see GoogleTranslatorSettingsPanel
     */
    static String GoogleTranslatorSettingsPanel_fileChooser_confirmButton() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GoogleTranslatorSettingsPanel.fileChooser.confirmButton");
    }
    /**
     * @return <i>JSON Files</i>
     * @see GoogleTranslatorSettingsPanel
     */
    static String GoogleTranslatorSettingsPanel_json_description() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GoogleTranslatorSettingsPanel.json.description");
    }
    /**
     * @return <i>Google Translate</i>
     * @see GoogleTranslator
     */
    static String GoogleTranslator_name_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GoogleTranslator.name.text");
    }
    private Bundle() {}
}
