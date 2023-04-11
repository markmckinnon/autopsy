package org.sleuthkit.autopsy.texttranslation;
/** Localizable strings for {@link org.sleuthkit.autopsy.texttranslation}. */
class Bundle {
    /**
     * @return <i>No text translator selected, translation is disabled.</i>
     * @see TranslationOptionsPanel
     */
    static String TranslationOptionsPanel_noTextTranslatorSelected_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TranslationOptionsPanel.noTextTranslatorSelected.text");
    }
    /**
     * @return <i>No text translators exist, translation is disabled.</i>
     * @see TranslationOptionsPanel
     */
    static String TranslationOptionsPanel_noTextTranslators_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TranslationOptionsPanel.noTextTranslators.text");
    }
    /**
     * @return <i>Unable to get selected text translator, translation is disabled.</i>
     * @see TranslationOptionsPanel
     */
    static String TranslationOptionsPanel_textTranslatorsUnavailable_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TranslationOptionsPanel.textTranslatorsUnavailable.text");
    }
    /**
     * @return <i>Translation disabled</i>
     * @see TranslationOptionsPanel
     */
    static String TranslationOptionsPanel_translationDisabled_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TranslationOptionsPanel.translationDisabled.text");
    }
    private Bundle() {}
}
