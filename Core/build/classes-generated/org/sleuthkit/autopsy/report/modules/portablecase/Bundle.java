package org.sleuthkit.autopsy.report.modules.portablecase;
/** Localizable strings for {@link org.sleuthkit.autopsy.report.modules.portablecase}. */
class Bundle {
    /**
     * @return <i>Compression canceled by user</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_compressCase_canceled() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.compressCase.canceled");
    }
    /**
     * @return <i>Error compressing case</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_compressCase_errorCompressingCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.compressCase.errorCompressingCase");
    }
    /**
     * @param Temp_folder_path Temp folder path
     * @return <i>Could not create temporary folder </i>{@code Temp_folder_path}
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_compressCase_errorCreatingTempFolder(Object Temp_folder_path) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.compressCase.errorCreatingTempFolder", Temp_folder_path);
    }
    /**
     * @return <i>Could not locate 7-Zip executable</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_compressCase_errorFinding7zip() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.compressCase.errorFinding7zip");
    }
    /**
     * @param File_name File name
     * @return <i>Copying file </i>{@code File_name}
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_copyContentToPortableCase_copyingFile(Object File_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.copyContentToPortableCase.copyingFile", File_name);
    }
    /**
     * @param case_folder case folder
     * @return <i>Case folder </i>{@code case_folder}<i> already exists</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_createCase_caseDirExists(Object case_folder) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.createCase.caseDirExists", case_folder);
    }
    /**
     * @return <i>Error creating case</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_createCase_errorCreatingCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.createCase.errorCreatingCase");
    }
    /**
     * @param folder folder
     * @return <i>Error creating folder </i>{@code folder}
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_createCase_errorCreatingFolder(Object folder) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.createCase.errorCreatingFolder", folder);
    }
    /**
     * @return <i>Error storing maximum database IDs</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_createCase_errorStoringMaxIds() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.createCase.errorStoringMaxIds");
    }
    /**
     * @return <i>Could not make report folder</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateCaseUcoReport_errorCreatingReportFolder() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateCaseUcoReport.errorCreatingReportFolder");
    }
    /**
     * @return <i>Problem while generating CASE-UCO report</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateCaseUcoReport_errorGeneratingCaseUcoReport() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateCaseUcoReport.errorGeneratingCaseUcoReport");
    }
    /**
     * @return <i>Creating a CASE-UCO report of the portable case</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateCaseUcoReport_startCaseUcoReportGeneration() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateCaseUcoReport.startCaseUcoReportGeneration");
    }
    /**
     * @return <i>Successfully created a CASE-UCO report of the portable case</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateCaseUcoReport_successCaseUcoReportGeneration() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateCaseUcoReport.successCaseUcoReportGeneration");
    }
    /**
     * @return <i>Current case has been closed</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_caseClosed() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateReport.caseClosed");
    }
    /**
     * @return <i>Compressing case...</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_compressingCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateReport.compressingCase");
    }
    /**
     * @param tag_name tag name
     * @return <i>Copying artifacts tagged as </i>{@code tag_name}<i>...</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_copyingArtifacts(Object tag_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateReport.copyingArtifacts", tag_name);
    }
    /**
     * @return <i>Copying application...</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_copyingAutopsy() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule_generateReport_copyingAutopsy");
    }
    /**
     * @param tag_name tag name
     * @return <i>Copying files tagged as </i>{@code tag_name}<i>...</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_copyingFiles(Object tag_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateReport.copyingFiles", tag_name);
    }
    /**
     * @return <i>Copying tags...</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_copyingTags() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateReport.copyingTags");
    }
    /**
     * @return <i>Creating portable case database...</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_creatingCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateReport.creatingCase");
    }
    /**
     * @return <i>Error copying tagged artifacts</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_errorCopyingArtifacts() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateReport.errorCopyingArtifacts");
    }
    /**
     * @return <i>Error copying application</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_errorCopyingAutopsy() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateReport.errorCopyingAutopsy");
    }
    /**
     * @return <i>Error copying tagged files</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_errorCopyingFiles() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateReport.errorCopyingFiles");
    }
    /**
     * @return <i>Error copying interesting files</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_errorCopyingInterestingFiles() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateReport.errorCopyingInterestingFiles");
    }
    /**
     * @return <i>Error copying interesting results</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_errorCopyingInterestingResults() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateReport.errorCopyingInterestingResults");
    }
    /**
     * @return <i>Error copying tags</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_errorCopyingTags() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateReport.errorCopyingTags");
    }
    /**
     * @return <i>Error creating image tags table</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_errorCreatingImageTagTable() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateReport.errorCreatingImageTagTable");
    }
    /**
     * @param attribute_type_name attribute type name
     * @return <i>Error looking up attribute type </i>{@code attribute_type_name}
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_errorLookingUpAttrType(Object attribute_type_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateReport.errorLookingUpAttrType", attribute_type_name);
    }
    /**
     * @return <i>Error while reading interesting items sets from case database</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_errorReadingSets() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateReport.errorReadingSets");
    }
    /**
     * @return <i>Error while reading tags from case database</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_errorReadingTags() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateReport.errorReadingTags");
    }
    /**
     * @return <i>Error loading intersting items</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_interestingItemError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateReport.interestingItemError");
    }
    /**
     * @return <i>No interesting files, results, or tagged items to copy</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_noContentToCopy() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateReport.noContentToCopy");
    }
    /**
     * @param output_folder output folder
     * @return <i>Output folder </i>{@code output_folder}<i> does not exist</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_outputDirDoesNotExist(Object output_folder) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateReport.outputDirDoesNotExist", output_folder);
    }
    /**
     * @param output_folder output folder
     * @return <i>Output folder </i>{@code output_folder}<i> is not a folder</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_outputDirIsNotDir(Object output_folder) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateReport.outputDirIsNotDir", output_folder);
    }
    /**
     * @return <i>Verifying selected parameters...</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_generateReport_verifying() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.generateReport.verifying");
    }
    /**
     * @return <i>Copies selected items to a new single-user case that can be easily shared</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_getDescription_description() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.getDescription.description");
    }
    /**
     * @return <i>Portable Case</i>
     * @see PortableCaseReportModule
     */
    static String PortableCaseReportModule_getName_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PortableCaseReportModule.getName.name");
    }
    private Bundle() {}
}
