package org.sleuthkit.autopsy.centralrepository.eventlisteners;
/** Localizable strings for {@link org.sleuthkit.autopsy.centralrepository.eventlisteners}. */
class Bundle {
    /**
     * @return <i>This data is used to:</i>
     * @see CentralRepositoryNotificationDialog
     */
    static String CentralRepositoryNotificationDialog_bulletHeader() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepositoryNotificationDialog.bulletHeader");
    }
    /**
     * @return <i>Ignore common items (files, domains, and accounts)</i>
     * @see CentralRepositoryNotificationDialog
     */
    static String CentralRepositoryNotificationDialog_bulletOne() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepositoryNotificationDialog.bulletOne");
    }
    /**
     * @return <i>Create personas that group accounts</i>
     * @see CentralRepositoryNotificationDialog
     */
    static String CentralRepositoryNotificationDialog_bulletThree() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepositoryNotificationDialog.bulletThree");
    }
    /**
     * @return <i>Identify where an item was previously seen</i>
     * @see CentralRepositoryNotificationDialog
     */
    static String CentralRepositoryNotificationDialog_bulletTwo() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepositoryNotificationDialog.bulletTwo");
    }
    /**
     * @return <i>To limit what is stored, use the Central Repository options panel.</i>
     * @see CentralRepositoryNotificationDialog
     */
    static String CentralRepositoryNotificationDialog_finalRemarks() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepositoryNotificationDialog.finalRemarks");
    }
    /**
     * @return <i>Autopsy stores data about each case in its Central Repository.</i>
     * @see CentralRepositoryNotificationDialog
     */
    static String CentralRepositoryNotificationDialog_header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CentralRepositoryNotificationDialog.header");
    }
    /**
     * @return <i>Central repository disabled</i>
     * @see Installer
     */
    static String Installer_centralRepoUpgradeFailed_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Installer.centralRepoUpgradeFailed.title");
    }
    /**
     * @return <i>Evidence</i>
     * @see CaseEventListener
     */
    static String caseeventlistener_evidencetag() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "caseeventlistener.evidencetag");
    }
    private Bundle() {}
}
