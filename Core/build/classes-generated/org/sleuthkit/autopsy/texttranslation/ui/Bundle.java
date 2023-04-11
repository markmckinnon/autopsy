package org.sleuthkit.autopsy.texttranslation.ui;
/** Localizable strings for {@link org.sleuthkit.autopsy.texttranslation.ui}. */
class Bundle {
    /**
     * @return <i>Original Text (Up to 25KB)</i>
     * @see TranslationContentPanel
     */
    static String TranslatedContentPanel_comboBoxOption_originalText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TranslatedContentPanel.comboBoxOption.originalText");
    }
    /**
     * @return <i>Translated Text</i>
     * @see TranslationContentPanel
     */
    static String TranslatedContentPanel_comboBoxOption_translatedText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TranslatedContentPanel.comboBoxOption.translatedText");
    }
    /**
     * @return <i>The machine translation software did not return any text.</i>
     * @see TranslateTextTask
     */
    static String TranslatedContentViewer_emptyTranslation() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TranslatedContentViewer.emptyTranslation");
    }
    /**
     * @param exception_message exception message
     * @return <i>An error occurred while extracting the text (</i>{@code exception_message}<i>).</i>
     * @see TranslatedTextViewer
     */
    static String TranslatedContentViewer_errorExtractingText(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TranslatedContentViewer.errorExtractingText", exception_message);
    }
    /**
     * @return <i>Extracting text, please wait...</i>
     * @see TranslatedTextViewer
     */
    static String TranslatedContentViewer_extractingText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TranslatedContentViewer.extractingText");
    }
    /**
     * @return <i>File has no text.</i>
     * @see TranslateTextTask
     */
    static String TranslatedContentViewer_fileHasNoText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TranslatedContentViewer.fileHasNoText");
    }
    /**
     * @return <i>The machine translation software was not found.</i>
     * @see TranslateTextTask
     */
    static String TranslatedContentViewer_noServiceProvider() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TranslatedContentViewer.noServiceProvider");
    }
    /**
     * @return <i>OCR is not enabled. To change, go to Tools->Options->Machine Translation</i>
     * @see TranslatedTextViewer
     */
    static String TranslatedContentViewer_ocrNotEnabled() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TranslatedContentViewer.ocrNotEnabled");
    }
    /**
     * @return <i>Translating text, please wait...</i>
     * @see TranslateTextTask
     */
    static String TranslatedContentViewer_translatingText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TranslatedContentViewer.translatingText");
    }
    /**
     * @param exception_message exception message
     * @return <i>An error occurred while translating the text (</i>{@code exception_message}<i>).</i>
     * @see TranslateTextTask
     */
    static String TranslatedContentViewer_translationException(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TranslatedContentViewer.translationException", exception_message);
    }
    /**
     * @return <i>Up to the first %dKB of text will be translated</i>
     * @see TranslatedTextViewer
     */
    static String TranslatedTextViewer_maxPayloadSize() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TranslatedTextViewer.maxPayloadSize");
    }
    /**
     * @return <i>Translation</i>
     * @see TranslatedTextViewer
     */
    static String TranslatedTextViewer_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TranslatedTextViewer.title");
    }
    /**
     * @return <i>Displays translated file text.</i>
     * @see TranslatedTextViewer
     */
    static String TranslatedTextViewer_toolTip() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TranslatedTextViewer.toolTip");
    }
    /**
     * @return <i>Autodetect language</i>
     * @see TranslationContentPanel
     */
    static String TranslationContentPanel_autoDetectOCR() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TranslationContentPanel.autoDetectOCR");
    }
    private Bundle() {}
}
