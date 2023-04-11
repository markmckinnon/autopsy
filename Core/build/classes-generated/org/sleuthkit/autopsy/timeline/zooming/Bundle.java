package org.sleuthkit.autopsy.timeline.zooming;
/** Localizable strings for {@link org.sleuthkit.autopsy.timeline.zooming}. */
class Bundle {
    /**
     * @return <i>Description Detail:</i>
     * @see ZoomSettingsPane
     */
    static String ZoomSettingsPane_descrLODLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ZoomSettingsPane.descrLODLabel.text");
    }
    /**
     * @return <i>Error responding to slider value change.</i>
     * @see ZoomSettingsPane
     */
    static String ZoomSettingsPane_sliderChange_errorText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ZoomSettingsPane.sliderChange.errorText");
    }
    /**
     * @return <i>Time Units:</i>
     * @see ZoomSettingsPane
     */
    static String ZoomSettingsPane_timeUnitLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ZoomSettingsPane.timeUnitLabel.text");
    }
    /**
     * @return <i>Event Type:</i>
     * @see ZoomSettingsPane
     */
    static String ZoomSettingsPane_typeZoomLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ZoomSettingsPane.typeZoomLabel.text");
    }
    /**
     * @return <i>Zoom</i>
     * @see ZoomSettingsPane
     */
    static String ZoomSettingsPane_zoomLabel_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ZoomSettingsPane.zoomLabel.text");
    }
    private Bundle() {}
}
