package org.sleuthkit.autopsy.livetriage;
/** Localizable strings for {@link org.sleuthkit.autopsy.livetriage}. */
class Bundle {
    /**
     * @return <i>Make Live Triage Drive</i>
     * @see CreateLiveTriageDriveAction
     */
    static String CTL_CreateLiveTriageDriveAction() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CTL_CreateLiveTriageDriveAction");
    }
    /**
     * @return <i>Finished creating live triage disk</i>
     * @see CreateLiveTriageDriveAction
     */
    static String CopyFilesWorker_done_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CopyFilesWorker.done.text");
    }
    /**
     * @return <i>Error copying live triage files</i>
     * @see CreateLiveTriageDriveAction
     */
    static String CopyFilesWorker_error_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CopyFilesWorker.error.text");
    }
    /**
     * @return <i>Could not location application directory</i>
     * @see CreateLiveTriageDriveAction
     */
    static String CreateLiveTriageDriveAction_appPathError_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CreateLiveTriageDriveAction.appPathError.message");
    }
    /**
     * @return <i>Error creating batch file</i>
     * @see CreateLiveTriageDriveAction
     */
    static String CreateLiveTriageDriveAction_batchFileError_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CreateLiveTriageDriveAction.batchFileError.message");
    }
    /**
     * @return <i>Could not copy application. Only works on installed version.</i>
     * @see CreateLiveTriageDriveAction
     */
    static String CreateLiveTriageDriveAction_copyError_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CreateLiveTriageDriveAction.copyError.message");
    }
    /**
     * @return <i>Error creating live triage disk</i>
     * @see CreateLiveTriageDriveAction
     */
    static String CreateLiveTriageDriveAction_error_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CreateLiveTriageDriveAction.error.title");
    }
    /**
     * @return <i>Executable could not be found</i>
     * @see CreateLiveTriageDriveAction
     */
    static String CreateLiveTriageDriveAction_exenotfound_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CreateLiveTriageDriveAction.exenotfound.message");
    }
    /**
     * @param drivePath drivePath
     * @return <i>Copying live triage files to </i>{@code drivePath}
     * @see CreateLiveTriageDriveAction
     */
    static String CreateLiveTriageDriveAction_progressBar_text(Object drivePath) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CreateLiveTriageDriveAction.progressBar.text", drivePath);
    }
    /**
     * @return <i>Please wait</i>
     * @see CreateLiveTriageDriveAction
     */
    static String CreateLiveTriageDriveAction_progressBar_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CreateLiveTriageDriveAction.progressBar.title");
    }
    /**
     * @return <i>Live triage drive created. Use RunFromUSB.bat to run the application</i>
     * @see CreateLiveTriageDriveAction
     */
    static String CreateLiveTriageDriveAction_success_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CreateLiveTriageDriveAction.success.message");
    }
    /**
     * @return <i>Success</i>
     * @see CreateLiveTriageDriveAction
     */
    static String CreateLiveTriageDriveAction_success_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CreateLiveTriageDriveAction.success.title");
    }
    /**
     * @return <i>Disk Name</i>
     * @see SelectDriveDialog
     */
    static String SelectDriveDialog_diskTable_column1_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SelectDriveDialog.diskTable.column1.title");
    }
    /**
     * @return <i>Disk Size</i>
     * @see SelectDriveDialog
     */
    static String SelectDriveDialog_diskTable_column2_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SelectDriveDialog.diskTable.column2.title");
    }
    /**
     * @return <i>Disks were not detected. On some systems it requires admin privileges</i>
     * @see SelectDriveDialog
     */
    static String SelectDriveDialog_errLabel_disksNotDetected_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SelectDriveDialog.errLabel.disksNotDetected.text");
    }
    /**
     * @return <i>Disks were not detected.</i>
     * @see SelectDriveDialog
     */
    static String SelectDriveDialog_errLabel_disksNotDetected_toolTipText() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SelectDriveDialog.errLabel.disksNotDetected.toolTipText");
    }
    /**
     * @return 
     * @see SelectDriveDialog
     */
    static String SelectDriveDialog_localDiskModel_loading_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SelectDriveDialog.localDiskModel.loading.msg");
    }
    /**
     * @return <i>Executable could not be found</i>
     * @see SelectDriveDialog
     */
    static String SelectDriveDialog_localDiskModel_nodrives_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SelectDriveDialog.localDiskModel.nodrives.msg");
    }
    /**
     * @return <i>Create Live Triage Drive</i>
     * @see SelectDriveDialog
     */
    static String SelectDriveDialog_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SelectDriveDialog.title");
    }
    private Bundle() {}
}
