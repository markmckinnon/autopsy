package org.sleuthkit.autopsy.corecomponentinterfaces;
/** Localizable strings for {@link org.sleuthkit.autopsy.corecomponentinterfaces}. */
class Bundle {
    /**
     * @return <i>Directory Tree</i>
     * @see CoreComponentControl
     */
    static String CoreComponentControl_CTL_DirectoryTreeTopComponent() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CoreComponentControl.CTL_DirectoryTreeTopComponent");
    }
    /**
     * @return <i>Favorites</i>
     * @see CoreComponentControl
     */
    static String CoreComponentControl_CTL_FavoritesTopComponent() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CoreComponentControl.CTL_FavoritesTopComponent");
    }
    private Bundle() {}
}
