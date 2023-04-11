package org.sleuthkit.autopsy.modules.embeddedfileextractor;
/** Localizable strings for {@link org.sleuthkit.autopsy.modules.embeddedfileextractor}. */
class Bundle {
    /**
     * @return <i>Unable to create output folder.</i>
     * @see EmbeddedFileExtractorIngestModule
     */
    static String CannotCreateOutputFolder() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CannotCreateOutputFolder");
    }
    /**
     * @return <i>Unable to run file type detection.</i>
     * @see EmbeddedFileExtractorIngestModule
     */
    static String CannotRunFileTypeDetection() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CannotRunFileTypeDetection");
    }
    /**
     * @return <i>Extracts embedded files (doc, docx, ppt, pptx, xls, xlsx, zip, rar, arj, 7z, gzip, bzip2, tar), schedules them for ingestion, and populates the directory tree with them.</i>
     * @see EmbeddedFileExtractorModuleFactory
     */
    static String EmbeddedFileExtractorIngestModule_ArchiveExtractor_moduleDesc_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EmbeddedFileExtractorIngestModule.ArchiveExtractor.moduleDesc.text");
    }
    /**
     * @return <i>Embedded File Extractor</i>
     * @see EmbeddedFileExtractorModuleFactory
     */
    static String EmbeddedFileExtractorIngestModule_ArchiveExtractor_moduleName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EmbeddedFileExtractorIngestModule.ArchiveExtractor.moduleName");
    }
    /**
     * @return <i>No open case available.</i>
     * @see EmbeddedFileExtractorIngestModule
     */
    static String EmbeddedFileExtractorIngestModule_NoOpenCase_errMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EmbeddedFileExtractorIngestModule.NoOpenCase.errMsg");
    }
    /**
     * @return <i>Unable to get MSOfficeEmbeddedContentExtractor.</i>
     * @see EmbeddedFileExtractorIngestModule
     */
    static String EmbeddedFileExtractorIngestModule_UnableToGetMSOfficeExtractor_errMsg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EmbeddedFileExtractorIngestModule.UnableToGetMSOfficeExtractor.errMsg");
    }
    /**
     * @return <i>Failed to create module output directory for Embedded File Extractor</i>
     * @see EmbeddedFileExtractorIngestModule
     */
    static String EmbeddedFileExtractor_make_output_dir_err() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EmbeddedFileExtractor_make_output_dir_err");
    }
    /**
     * @return <i>Failed to Unpack Files, with Password</i>
     * @see ExtractArchiveWithPasswordAction
     */
    static String ExtractArchiveWithPasswordAction_extractFailed_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExtractArchiveWithPasswordAction.extractFailed.title");
    }
    /**
     * @return <i>Unzip contents with password</i>
     * @see ExtractArchiveWithPasswordAction
     */
    static String ExtractArchiveWithPasswordAction_name_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExtractArchiveWithPasswordAction.name.text");
    }
    /**
     * @param archiveFile archiveFile
     * @return <i>Unpacking contents of archive: </i>{@code archiveFile}
     * @see ExtractArchiveWithPasswordAction
     */
    static String ExtractArchiveWithPasswordAction_progress_text(Object archiveFile) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExtractArchiveWithPasswordAction.progress.text", archiveFile);
    }
    /**
     * @return <i>Enter Password</i>
     * @see ExtractArchiveWithPasswordAction
     */
    static String ExtractArchiveWithPasswordAction_prompt_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExtractArchiveWithPasswordAction.prompt.text");
    }
    /**
     * @return <i>Enter Password</i>
     * @see ExtractArchiveWithPasswordAction
     */
    static String ExtractArchiveWithPasswordAction_prompt_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ExtractArchiveWithPasswordAction.prompt.title");
    }
    /**
     * @return <i>Failed to index encryption detected artifact for keyword search.</i>
     * @see SevenZipExtractor
     */
    static String SevenZipExtractor_indexError_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SevenZipExtractor.indexError.message");
    }
    /**
     * @param _rootArchive  rootArchive
     * @return <i>Zip Bomb Detected </i>{@code _rootArchive}
     * @see SevenZipExtractor
     */
    static String SevenZipExtractor_zipBombArtifactCreation_text(Object _rootArchive) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SevenZipExtractor.zipBombArtifactCreation.text", _rootArchive);
    }
    /**
     * @return <i>Unable to initialize 7Zip libraries.</i>
     * @see EmbeddedFileExtractorIngestModule
     */
    static String UnableToInitializeLibraries() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "UnableToInitializeLibraries");
    }
    private Bundle() {}
}
