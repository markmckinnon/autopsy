package org.sleuthkit.autopsy.machinesettings;
/** Localizable strings for {@link org.sleuthkit.autopsy.machinesettings}. */
class Bundle {
    /**
     * @param path path
     * @return <i>There was an error creating the temp directory for path: </i>{@code path}
     * @see UserMachinePreferences
     */
    static String UserMachinePreferences_validateTempDirectory_errorOnCreate_text(Object path) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UserMachinePreferences_validateTempDirectory_errorOnCreate_text", path);
    }
    /**
     * @param path path
     * @return <i>There was an error reading or writing to temp directory path: </i>{@code path}
     * @see UserMachinePreferences
     */
    static String UserMachinePreferences_validateTempDirectory_errorOnReadWrite_text(Object path) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UserMachinePreferences_validateTempDirectory_errorOnReadWrite_text", path);
    }
    private Bundle() {}
}
