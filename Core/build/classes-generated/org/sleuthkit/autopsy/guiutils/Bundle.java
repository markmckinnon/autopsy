package org.sleuthkit.autopsy.guiutils;
/** Localizable strings for {@link org.sleuthkit.autopsy.guiutils}. */
class Bundle {
    /**
     * @return <i>An error occurred</i>
     * @see StatusIconCellRenderer
     */
    static String StatusIconCellRenderer_tooltiptext_error() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "StatusIconCellRenderer.tooltiptext.error");
    }
    /**
     * @return <i>OK</i>
     * @see StatusIconCellRenderer
     */
    static String StatusIconCellRenderer_tooltiptext_ok() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "StatusIconCellRenderer.tooltiptext.ok");
    }
    /**
     * @return <i>A warning occurred</i>
     * @see StatusIconCellRenderer
     */
    static String StatusIconCellRenderer_tooltiptext_warning() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "StatusIconCellRenderer.tooltiptext.warning");
    }
    private Bundle() {}
}
