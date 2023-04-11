package org.sleuthkit.autopsy.report.modules.taggedhashes;
/** Localizable strings for {@link org.sleuthkit.autopsy.report.modules.taggedhashes}. */
class Bundle {
    /**
     * @return <i>No hash set selected for export.</i>
     * @see SaveTaggedHashesToHashDb
     */
    static String AddTaggedHashesToHashDb_error_noHashSetsSelected() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddTaggedHashesToHashDb.error.noHashSetsSelected");
    }
    /**
     * @return <i>No tags selected for export.</i>
     * @see SaveTaggedHashesToHashDb
     */
    static String AddTaggedHashesToHashDb_error_noTagsSelected() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddTaggedHashesToHashDb.error.noTagsSelected");
    }
    /**
     * @return <i>Exception while getting open case.</i>
     * @see SaveTaggedHashesToHashDb
     */
    static String AddTaggedHashesToHashDb_error_unableToOpenCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddTaggedHashesToHashDb.error.unableToOpenCase");
    }
    private Bundle() {}
}
