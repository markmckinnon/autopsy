package org.sleuthkit.autopsy.menuactions;
/** Localizable strings for {@link org.sleuthkit.autopsy.menuactions}. */
class Bundle {
    /**
     * @return <i>Content Viewers</i>
     * @see DataContentDynamicMenu
     */
    static String DataContentDynamicMenu_contentViewers_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataContentDynamicMenu.contentViewers.text");
    }
    /**
     * @return <i>Main</i>
     * @see DataContentDynamicMenu
     */
    static String DataContentDynamicMenu_mainContentViewer_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DataContentDynamicMenu.mainContentViewer.name");
    }
    /**
     * @return <i>Result Viewers</i>
     * @see SearchResultMenu
     */
    static String SearchResultMenu_resultViewers_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchResultMenu.resultViewers.text");
    }
    private Bundle() {}
}
