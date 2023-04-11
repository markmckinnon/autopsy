package org.sleuthkit.autopsy.centralrepository;
/** Localizable strings for {@link org.sleuthkit.autopsy.centralrepository}. */
class Bundle {
    /**
     * @return <i>Add/Edit Central Repository Comment</i>
     * @see AddEditCentralRepoCommentAction
     */
    static String AddEditCentralRepoCommentAction_menuItemText_addEditCentralRepoComment() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddEditCentralRepoCommentAction.menuItemText.addEditCentralRepoComment");
    }
    /**
     * @return <i>Add/Edit Central Repository Comment (Empty File)</i>
     * @see AddEditCentralRepoCommentAction
     */
    static String AddEditCentralRepoCommentAction_menuItemText_addEditCentralRepoCommentEmptyFile() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddEditCentralRepoCommentAction.menuItemText.addEditCentralRepoCommentEmptyFile");
    }
    /**
     * @return <i>Add/Edit Central Repository Comment (No MD5 Hash)</i>
     * @see AddEditCentralRepoCommentAction
     */
    static String AddEditCentralRepoCommentAction_menuItemText_addEditCentralRepoCommentNoMD5() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddEditCentralRepoCommentAction.menuItemText.addEditCentralRepoCommentNoMD5");
    }
    /**
     * @return <i>Add/Edit Central Repository Comment</i>
     * @see CentralRepoCommentDialog
     */
    static String CentralRepoCommentDialog_title_addEditCentralRepoComment() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepoCommentDialog.title.addEditCentralRepoComment");
    }
    private Bundle() {}
}
