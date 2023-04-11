package org.sleuthkit.autopsy.contentviewers.osaccount;
/** Localizable strings for {@link org.sleuthkit.autopsy.contentviewers.osaccount}. */
class Bundle {
    /**
     * @return <i>Administrator</i>
     * @see OsAccountDataPanel
     */
    static String OsAccountDataPanel_administrator_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OsAccountDataPanel_administrator_title");
    }
    /**
     * @return <i>Address</i>
     * @see OsAccountDataPanel
     */
    static String OsAccountDataPanel_basic_address() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OsAccountDataPanel_basic_address");
    }
    /**
     * @return <i>Administrator</i>
     * @see OsAccountDataPanel
     */
    static String OsAccountDataPanel_basic_admin() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OsAccountDataPanel_basic_admin");
    }
    /**
     * @return <i>Creation Date</i>
     * @see OsAccountDataPanel
     */
    static String OsAccountDataPanel_basic_creationDate() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OsAccountDataPanel_basic_creationDate");
    }
    /**
     * @return <i>Full Name</i>
     * @see OsAccountDataPanel
     */
    static String OsAccountDataPanel_basic_fullname() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OsAccountDataPanel_basic_fullname");
    }
    /**
     * @return <i>Login</i>
     * @see OsAccountDataPanel
     */
    static String OsAccountDataPanel_basic_login() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OsAccountDataPanel_basic_login");
    }
    /**
     * @return <i>Object ID</i>
     * @see OsAccountDataPanel
     */
    static String OsAccountDataPanel_basic_objId() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OsAccountDataPanel_basic_objId");
    }
    /**
     * @return <i>Basic Properties</i>
     * @see OsAccountDataPanel
     */
    static String OsAccountDataPanel_basic_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OsAccountDataPanel_basic_title");
    }
    /**
     * @return <i>Type</i>
     * @see OsAccountDataPanel
     */
    static String OsAccountDataPanel_basic_type() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OsAccountDataPanel_basic_type");
    }
    /**
     * @return <i>Last Login</i>
     * @see OsAccountDataPanel
     */
    static String OsAccountDataPanel_data_accessed_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OsAccountDataPanel_data_accessed_title");
    }
    /**
     * @return <i>Login Count</i>
     * @see OsAccountDataPanel
     */
    static String OsAccountDataPanel_host_count_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OsAccountDataPanel_host_count_title");
    }
    /**
     * @param hostName hostName
     * @return {@code hostName}<i> Details</i>
     * @see OsAccountDataPanel
     */
    static String OsAccountDataPanel_host_section_title(Object hostName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OsAccountDataPanel_host_section_title", hostName);
    }
    /**
     * @return <i>Address</i>
     * @see OsAccountDataPanel
     */
    static String OsAccountDataPanel_realm_address() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OsAccountDataPanel_realm_address");
    }
    /**
     * @return <i>Confidence</i>
     * @see OsAccountDataPanel
     */
    static String OsAccountDataPanel_realm_confidence() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OsAccountDataPanel_realm_confidence");
    }
    /**
     * @return <i>Name</i>
     * @see OsAccountDataPanel
     */
    static String OsAccountDataPanel_realm_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OsAccountDataPanel_realm_name");
    }
    /**
     * @return <i>Scope</i>
     * @see OsAccountDataPanel
     */
    static String OsAccountDataPanel_realm_scope() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OsAccountDataPanel_realm_scope");
    }
    /**
     * @return <i>Realm Properties</i>
     * @see OsAccountDataPanel
     */
    static String OsAccountDataPanel_realm_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OsAccountDataPanel_realm_title");
    }
    /**
     * @return <i>Unknown</i>
     * @see OsAccountDataPanel
     */
    static String OsAccountDataPanel_realm_unknown() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OsAccountDataPanel_realm_unknown");
    }
    /**
     * @return <i>OS Account</i>
     * @see OsAccountViewer
     */
    static String OsAccountViewer_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OsAccountViewer_title");
    }
    /**
     * @return <i>Viewer for Operating System accounts related to the selected node.</i>
     * @see OsAccountViewer
     */
    static String OsAccountViewer_tooltip() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "OsAccountViewer_tooltip");
    }
    private Bundle() {}
}
