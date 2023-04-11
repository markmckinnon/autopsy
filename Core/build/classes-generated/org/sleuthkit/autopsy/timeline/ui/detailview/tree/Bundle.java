package org.sleuthkit.autopsy.timeline.ui.detailview.tree;
/** Localizable strings for {@link org.sleuthkit.autopsy.timeline.ui.detailview.tree}. */
class Bundle {
    /**
     * @return <i>Sort By:</i>
     * @see EventsTree
     */
    static String EventsTree_Label_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EventsTree.Label.text");
    }
    /**
     * @return <i>Count</i>
     * @see TreeComparator
     */
    static String TreeComparator_Count_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TreeComparator.Count.displayName");
    }
    /**
     * @return <i>Description</i>
     * @see TreeComparator
     */
    static String TreeComparator_Description_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TreeComparator.Description.displayName");
    }
    /**
     * @return <i>Type</i>
     * @see TreeComparator
     */
    static String TreeComparator_Type_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TreeComparator.Type.displayName");
    }
    private Bundle() {}
}
