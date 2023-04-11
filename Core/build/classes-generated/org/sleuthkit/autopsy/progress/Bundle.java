package org.sleuthkit.autopsy.progress;
/** Localizable strings for {@link org.sleuthkit.autopsy.progress}. */
class Bundle {
    /**
     * @return <i>Cancelling...</i>
     * @see TaskCancellable
     */
    static String TaskCanceller_progress_cancellingMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TaskCanceller.progress.cancellingMessage");
    }
    private Bundle() {}
}
