package org.sleuthkit.autopsy.core;
/** Localizable strings for {@link org.sleuthkit.autopsy.core}. */
class Bundle {
    /**
     * @return <i>Ingest is running, are you sure you want to exit?</i>
     * @see Installer
     */
    static String Installer_closing_confirmationDialog_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Installer.closing.confirmationDialog.message");
    }
    /**
     * @return <i>Ingest is Running</i>
     * @see Installer
     */
    static String Installer_closing_confirmationDialog_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Installer.closing.confirmationDialog.title");
    }
    /**
     * @param exception_message exception message
     * @return <i>Error closing case: </i>{@code exception_message}
     * @see Installer
     */
    static String Installer_closing_messageBox_caseCloseExceptionMessage(Object exception_message) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Installer.closing.messageBox.caseCloseExceptionMessage", exception_message);
    }
    private Bundle() {}
}
