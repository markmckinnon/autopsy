package org.sleuthkit.autopsy.coreutils;
/** Localizable strings for {@link org.sleuthkit.autopsy.coreutils}. */
class Bundle {
    /**
     * @return <i>Audio</i>
     * @see FileTypeUtils
     */
    static String FileTypeCategory_Audio_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileTypeCategory.Audio.displayName");
    }
    /**
     * @return <i>Documents</i>
     * @see FileTypeUtils
     */
    static String FileTypeCategory_Documents_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileTypeCategory.Documents.displayName");
    }
    /**
     * @return <i>Executables</i>
     * @see FileTypeUtils
     */
    static String FileTypeCategory_Executables_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileTypeCategory.Executables.displayName");
    }
    /**
     * @return <i>Image</i>
     * @see FileTypeUtils
     */
    static String FileTypeCategory_Image_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileTypeCategory.Image.displayName");
    }
    /**
     * @return <i>Media</i>
     * @see FileTypeUtils
     */
    static String FileTypeCategory_Media_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileTypeCategory.Media.displayName");
    }
    /**
     * @return <i>Video</i>
     * @see FileTypeUtils
     */
    static String FileTypeCategory_Video_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileTypeCategory.Video.displayName");
    }
    /**
     * @return <i>Visual</i>
     * @see FileTypeUtils
     */
    static String FileTypeCategory_Visual_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "FileTypeCategory.Visual.displayName");
    }
    /**
     * @param file_name file name
     * @return <i>Generating preview for </i>{@code file_name}
     * @see ImageUtils
     */
    static String GetOrGenerateThumbnailTask_generatingPreviewFor(Object file_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GetOrGenerateThumbnailTask.generatingPreviewFor", file_name);
    }
    /**
     * @param file_name file name
     * @return <i>Loading thumbnail for </i>{@code file_name}
     * @see ImageUtils
     */
    static String GetOrGenerateThumbnailTask_loadingThumbnailFor(Object file_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GetOrGenerateThumbnailTask.loadingThumbnailFor", file_name);
    }
    /**
     * @return <i>OpenCV FFMpeg library failed to load, see log for more details</i>
     * @see ImageUtils
     */
    static String ImageUtils_ffmpegLoadedError_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ImageUtils.ffmpegLoadedError.msg");
    }
    /**
     * @return <i>OpenCV FFMpeg</i>
     * @see ImageUtils
     */
    static String ImageUtils_ffmpegLoadedError_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ImageUtils.ffmpegLoadedError.title");
    }
    /**
     * @param file_name file name
     * @return <i>Reading image: </i>{@code file_name}
     * @see ImageUtils
     */
    static String ReadImageTask_mesageText(Object file_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReadImageTask.mesageText", file_name);
    }
    /**
     * @param file_name file name
     * @return <i>extracting temporary file </i>{@code file_name}
     * @see VideoUtils
     */
    static String VideoUtils_genVideoThumb_progress_text(Object file_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "VideoUtils.genVideoThumb.progress.text", file_name);
    }
    private Bundle() {}
}
