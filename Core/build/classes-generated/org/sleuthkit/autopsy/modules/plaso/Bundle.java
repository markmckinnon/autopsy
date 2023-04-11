package org.sleuthkit.autopsy.modules.plaso;
/** Localizable strings for {@link org.sleuthkit.autopsy.modules.plaso}. */
class Bundle {
    /**
     * @param file_that_events_are_from file that events are from
     * @return <i>Adding events to case: </i>{@code file_that_events_are_from}
     * @see PlasoIngestModule
     */
    static String PlasoIngestModule_artifact_progress(Object file_that_events_are_from) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoIngestModule.artifact.progress", file_that_events_are_from);
    }
    /**
     * @return <i>Cannot find image file name and path</i>
     * @see PlasoIngestModule
     */
    static String PlasoIngestModule_bad_imageFile() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoIngestModule.bad.imageFile");
    }
    /**
     * @return <i>Plaso Processing Completed</i>
     * @see PlasoIngestModule
     */
    static String PlasoIngestModule_completed() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoIngestModule.completed");
    }
    /**
     * @return <i>Cancelled Plaso Artifact Creation </i>
     * @see PlasoIngestModule
     */
    static String PlasoIngestModule_create_artifacts_cancelled() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoIngestModule.create.artifacts.cancelled");
    }
    /**
     * @return <i>Skipping non-disk image datasource</i>
     * @see PlasoIngestModule
     */
    static String PlasoIngestModule_dataSource_not_an_image() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoIngestModule.dataSource.not.an.image");
    }
    /**
     * @return <i>Error creating Plaso module output directory.</i>
     * @see PlasoIngestModule
     */
    static String PlasoIngestModule_error_creating_output_dir() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoIngestModule.error.creating.output.dir");
    }
    /**
     * @return <i>Error running log2timeline, see log file.</i>
     * @see PlasoIngestModule
     */
    static String PlasoIngestModule_error_running_log2timeline() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoIngestModule.error.running.log2timeline");
    }
    /**
     * @return <i>Error running Psort, see log file.</i>
     * @see PlasoIngestModule
     */
    static String PlasoIngestModule_error_running_psort() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoIngestModule.error.running.psort");
    }
    /**
     * @return <i>Event Date Time</i>
     * @see PlasoIngestModule
     */
    static String PlasoIngestModule_event_datetime() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoIngestModule.event.datetime");
    }
    /**
     * @return <i>Event Description</i>
     * @see PlasoIngestModule
     */
    static String PlasoIngestModule_event_description() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoIngestModule.event.description");
    }
    /**
     * @return <i>Exception Posting artifact.</i>
     * @see PlasoIngestModule
     */
    static String PlasoIngestModule_exception_posting_artifact() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoIngestModule.exception.posting.artifact");
    }
    /**
     * @return <i>Plaso Executable Not Found.</i>
     * @see PlasoIngestModule
     */
    static String PlasoIngestModule_executable_not_found() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoIngestModule.executable.not.found");
    }
    /**
     * @return <i>Plaso</i>
     * @see PlasoIngestModule
     */
    static String PlasoIngestModule_has_run() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoIngestModule.has.run");
    }
    /**
     * @return <i>Plaso database was empty.</i>
     * @see PlasoIngestModule
     */
    static String PlasoIngestModule_info_empty_database() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoIngestModule.info.empty.database");
    }
    /**
     * @return <i>Log2timeline run was canceled</i>
     * @see PlasoIngestModule
     */
    static String PlasoIngestModule_log2timeline_cancelled() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoIngestModule.log2timeline.cancelled");
    }
    /**
     * @return <i>psort run was canceled</i>
     * @see PlasoIngestModule
     */
    static String PlasoIngestModule_psort_cancelled() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoIngestModule.psort.cancelled");
    }
    /**
     * @return <i>Plaso returned an error when sorting events.  Results are not complete.</i>
     * @see PlasoIngestModule
     */
    static String PlasoIngestModule_psort_fail() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoIngestModule.psort.fail");
    }
    /**
     * @return <i>Plaso module requires windows.</i>
     * @see PlasoIngestModule
     */
    static String PlasoIngestModule_requires_windows() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoIngestModule.requires.windows");
    }
    /**
     * @return <i>Running Psort</i>
     * @see PlasoIngestModule
     */
    static String PlasoIngestModule_running_psort() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoIngestModule.running.psort");
    }
    /**
     * @return <i>Starting Log2timeline</i>
     * @see PlasoIngestModule
     */
    static String PlasoIngestModule_starting_log2timeline() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoIngestModule.starting.log2timeline");
    }
    /**
     * @return <i>Expected settings argument to be instanceof PlasoModuleSettings</i>
     * @see PlasoModuleFactory
     */
    static String PlasoModuleFactory_ingestJobSettings_exception_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoModuleFactory.ingestJobSettings.exception.msg");
    }
    /**
     * @return <i>Runs Plaso against a Data Source.</i>
     * @see PlasoModuleFactory
     */
    static String PlasoModuleFactory_moduleDesc() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoModuleFactory_moduleDesc");
    }
    /**
     * @return <i>Plaso</i>
     * @see PlasoModuleFactory
     */
    static String PlasoModuleFactory_moduleName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PlasoModuleFactory_moduleName");
    }
    private Bundle() {}
}
