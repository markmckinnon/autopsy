package org.sleuthkit.autopsy.apputils;
/** Localizable strings for {@link org.sleuthkit.autopsy.apputils}. */
class Bundle {
    /**
     * @return <i>Reset Windows</i>
     * @see ResetWindowsAction
     */
    static String CTL_ResetWindowsAction() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CTL_ResetWindowsAction");
    }
    /**
     * @return <i>Unable to close the current case, the software will restart and the windows locations will reset the next time the software is closed.</i>
     * @see ResetWindowsAction
     */
    static String ResetWindowAction_caseCloseFailure_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ResetWindowAction.caseCloseFailure.text");
    }
    /**
     * @return <i>Unable to save current case path, the software will restart and the windows locations will reset but the current case will not be opened upon restart.</i>
     * @see ResetWindowsAction
     */
    static String ResetWindowAction_caseSaveMetadata_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ResetWindowAction.caseSaveMetadata.text");
    }
    /**
     * @return <i>In order to perform the resetting of window locations the software will close and restart. If a case is currently open, it will be closed. If ingest or a search is currently running, it will be terminated. Are you sure you want to restart the software to reset all window locations?</i>
     * @see ResetWindowsAction
     */
    static String ResetWindowAction_confirm_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ResetWindowAction.confirm.text");
    }
    private Bundle() {}
}
