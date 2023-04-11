package org.sleuthkit.autopsy.directorytree.actionhelpers;
/** Localizable strings for {@link org.sleuthkit.autopsy.directorytree.actionhelpers}. */
class Bundle {
    /**
     * @param fileName fileName
     * @return <i>A file already exists at </i>{@code fileName}<i>.  Do you want to overwrite the existing file?</i>
     * @see ExtractActionHelper
     */
    static String ExtractActionHelper_extractOverwrite_msg(Object fileName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExtractActionHelper.extractOverwrite.msg", fileName);
    }
    /**
     * @return <i>Export to csv file</i>
     * @see ExtractActionHelper
     */
    static String ExtractActionHelper_extractOverwrite_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExtractActionHelper.extractOverwrite.title");
    }
    /**
     * @return <i>No open case available.</i>
     * @see ExtractActionHelper
     */
    static String ExtractActionHelper_noOpenCase_errMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExtractActionHelper.noOpenCase.errMsg");
    }
    /**
     * @param outputFolderName outputFolderName
     * @return <i>Extracting to </i>{@code outputFolderName}
     * @see ExtractActionHelper
     */
    static String ExtractActionHelper_progress_extracting(Object outputFolderName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExtractActionHelper.progress.extracting", outputFolderName);
    }
    /**
     * @param fileName fileName
     * @return <i>Extracting file: </i>{@code fileName}
     * @see ExtractActionHelper
     */
    static String ExtractActionHelper_progress_fileExtracting(Object fileName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExtractActionHelper.progress.fileExtracting", fileName);
    }
    private Bundle() {}
}
