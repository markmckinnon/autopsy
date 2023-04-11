package org.sleuthkit.autopsy.contentviewers.textcontentviewer;
/** Localizable strings for {@link org.sleuthkit.autopsy.contentviewers.textcontentviewer}. */
class Bundle {
    /**
     * @return <i>Loading text...</i>
     * @see StringsContentPanel
     */
    static String StringContentPanel_Loading_String() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "StringContentPanel_Loading_String");
    }
    /**
     * @return <i>Text</i>
     * @see TextContentViewerPanel
     */
    static String TextContentViewerPanel_defaultName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TextContentViewerPanel.defaultName");
    }
    /**
     * @return <i>Text</i>
     * @see TextContentViewer
     */
    static String TextContentViewer_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TextContentViewer.title");
    }
    /**
     * @return <i>Displays text associated with the selected item</i>
     * @see TextContentViewer
     */
    static String TextContentViewer_tooltip() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TextContentViewer.tooltip");
    }
    private Bundle() {}
}
