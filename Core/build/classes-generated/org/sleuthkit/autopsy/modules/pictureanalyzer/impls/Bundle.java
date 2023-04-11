package org.sleuthkit.autopsy.modules.pictureanalyzer.impls;
/** Localizable strings for {@link org.sleuthkit.autopsy.modules.pictureanalyzer.impls}. */
class Bundle {
    /**
     * @return <i>EXIF metadata data exists for this file.</i>
     * @see EXIFProcessor
     */
    static String ExifProcessor_userContent_description() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExifProcessor.userContent.description");
    }
    private Bundle() {}
}
