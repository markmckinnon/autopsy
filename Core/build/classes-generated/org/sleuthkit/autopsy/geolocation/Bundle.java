package org.sleuthkit.autopsy.geolocation;
/** Localizable strings for {@link org.sleuthkit.autopsy.geolocation}. */
class Bundle {
    /**
     * @return <i>Geolocation</i>
     * @see OpenGeolocationAction
     */
    static String CTL_OpenGeolocation() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CTL_OpenGeolocation");
    }
    /**
     * @return <i>No Geolocation artifacts found</i>
     * @see GeolocationTopComponent
     */
    static String GLTopComponent_No_dataSource_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GLTopComponent_No_dataSource_Title");
    }
    /**
     * @return <i>There are no data sources with Geolocation artifacts found.</i>
     * @see GeolocationTopComponent
     */
    static String GLTopComponent_No_dataSource_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GLTopComponent_No_dataSource_message");
    }
    /**
     * @return <i>An error occurred during waypoint initilization. Geolocation data maybe incomplete.</i>
     * @see GeolocationTopComponent
     */
    static String GLTopComponent_initilzation_error() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GLTopComponent_initilzation_error");
    }
    /**
     * @return <i>Geolocation</i>
     * @see GeolocationTopComponent
     */
    static String GLTopComponent_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GLTopComponent_name");
    }
    /**
     * @return <i>Types</i>
     * @see GeoFilterPanel
     */
    static String GeoFilterPanel_ArtifactType_List_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeoFilterPanel_ArtifactType_List_Title");
    }
    /**
     * @return <i>Data Sources</i>
     * @see GeoFilterPanel
     */
    static String GeoFilterPanel_DataSource_List_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeoFilterPanel_DataSource_List_Title");
    }
    /**
     * @return <i>Unable to apply filter, please select one or more artifact types.</i>
     * @see GeoFilterPanel
     */
    static String GeoFilterPanel_empty_artifactType() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeoFilterPanel_empty_artifactType");
    }
    /**
     * @return <i>Unable to apply filter, please select one or more data sources.</i>
     * @see GeoFilterPanel
     */
    static String GeoFilterPanel_empty_dataSource() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeoFilterPanel_empty_dataSource");
    }
    /**
     * @return <i>Filter Failure</i>
     * @see GeolocationTopComponent
     */
    static String GeoTopComponent_filer_data_invalid_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeoTopComponent_filer_data_invalid_Title");
    }
    /**
     * @return <i>Unable to run waypoint filter.<br>Please select one or more data sources.</i>
     * @see GeolocationTopComponent
     */
    static String GeoTopComponent_filer_data_invalid_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeoTopComponent_filer_data_invalid_msg");
    }
    /**
     * @return <i>Filter Failure</i>
     * @see GeolocationTopComponent
     */
    static String GeoTopComponent_filter_exception_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeoTopComponent_filter_exception_Title");
    }
    /**
     * @return <i>Exception occurred during waypoint filtering.</i>
     * @see GeolocationTopComponent
     */
    static String GeoTopComponent_filter_exception_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeoTopComponent_filter_exception_msg");
    }
    /**
     * @return <i>No Waypoints Found</i>
     * @see GeolocationTopComponent
     */
    static String GeoTopComponent_no_waypoints_returned_Title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeoTopComponent_no_waypoints_returned_Title");
    }
    /**
     * @return <i>Applied filter failed to find waypoints that matched criteria.<br>Revise filter options and try again.</i>
     * @see GeolocationTopComponent
     */
    static String GeoTopComponent_no_waypoints_returned_mgs() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeoTopComponent_no_waypoints_returned_mgs");
    }
    /**
     * @return <i>The supplied OSM tile server address is invalid.<br>Please supply a well formed url prefixed with http://</i>
     * @see GeolocationSettingsPanel
     */
    static String GeolocationSettingsPanel_malformed_url_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeolocationSettingsPanel_malformed_url_message");
    }
    /**
     * @return <i>Malformed URL</i>
     * @see GeolocationSettingsPanel
     */
    static String GeolocationSettingsPanel_malformed_url_message_tile() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeolocationSettingsPanel_malformed_url_message_tile");
    }
    /**
     * @return <i>OSM tile server test failed.<br>Unable to connect to server.</i>
     * @see GeolocationSettingsPanel
     */
    static String GeolocationSettingsPanel_osm_server_test_fail_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeolocationSettingsPanel_osm_server_test_fail_message");
    }
    /**
     * @return <i>Error</i>
     * @see GeolocationSettingsPanel
     */
    static String GeolocationSettingsPanel_osm_server_test_fail_message_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeolocationSettingsPanel_osm_server_test_fail_message_title");
    }
    /**
     * @return <i>The provided OSM tile server address is valid.</i>
     * @see GeolocationSettingsPanel
     */
    static String GeolocationSettingsPanel_osm_server_test_success_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeolocationSettingsPanel_osm_server_test_success_message");
    }
    /**
     * @return <i>Success</i>
     * @see GeolocationSettingsPanel
     */
    static String GeolocationSettingsPanel_osm_server_test_success_message_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeolocationSettingsPanel_osm_server_test_success_message_title");
    }
    /**
     * @return <i>The file supplied does not exist.<br>Please verify that the file exists and try again.</i>
     * @see GeolocationSettingsPanel
     */
    static String GeolocationSettings_mbtile_does_not_exist_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeolocationSettings_mbtile_does_not_exist_message");
    }
    /**
     * @return <i>File Not Found</i>
     * @see GeolocationSettingsPanel
     */
    static String GeolocationSettings_mbtile_does_not_exist_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeolocationSettings_mbtile_does_not_exist_title");
    }
    /**
     * @return <i>The supplied file is not a raster tile file.</i>
     * @see GeolocationSettingsPanel
     */
    static String GeolocationSettings_mbtile_not_valid_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeolocationSettings_mbtile_not_valid_message");
    }
    /**
     * @return <i>File Not Valid</i>
     * @see GeolocationSettingsPanel
     */
    static String GeolocationSettings_mbtile_not_valid_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeolocationSettings_mbtile_not_valid_title");
    }
    /**
     * @return <i>The supplied file is a valid mbtile raster file.</i>
     * @see GeolocationSettingsPanel
     */
    static String GeolocationSettings_mbtile_test_success_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeolocationSettings_mbtile_test_success_message");
    }
    /**
     * @return <i>Success</i>
     * @see GeolocationSettingsPanel
     */
    static String GeolocationSettings_mbtile_test_success_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeolocationSettings_mbtile_test_success_title");
    }
    /**
     * @return <i>The supplied file path is empty.<br>Please supply a valid file path.</i>
     * @see GeolocationSettingsPanel
     */
    static String GeolocationSettings_path_not_valid_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeolocationSettings_path_not_valid_message");
    }
    /**
     * @return <i>File Not Valid</i>
     * @see GeolocationSettingsPanel
     */
    static String GeolocationSettings_path_not_valid_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeolocationSettings_path_not_valid_title");
    }
    /**
     * @return <i>KML Report</i>
     * @see GeolocationTopComponent
     */
    static String GeolocationTC_KML_report_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeolocationTC_KML_report_title");
    }
    /**
     * @return <i>Failed to connect to map title source.<br>Please review map source in Options dialog.</i>
     * @see GeolocationTopComponent
     */
    static String GeolocationTC_connection_failure_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeolocationTC_connection_failure_message");
    }
    /**
     * @return <i>Connection Failure</i>
     * @see GeolocationTopComponent
     */
    static String GeolocationTC_connection_failure_message_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeolocationTC_connection_failure_message_title");
    }
    /**
     * @return <i>Unable to generate KML report due to a lack of waypoints.<br>Please make sure there are waypoints visible before generating the KML report</i>
     * @see GeolocationTopComponent
     */
    static String GeolocationTC_empty_waypoint_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeolocationTC_empty_waypoint_message");
    }
    /**
     * @return <i>KML Report Progress</i>
     * @see GeolocationTopComponent
     */
    static String GeolocationTC_report_progress_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeolocationTC_report_progress_title");
    }
    /**
     * @return <i>There was an error gathering some GPS Track Data.  Some results have been excluded.</i>
     * @see GeolocationTopComponent
     */
    static String GeolocationTopComponent_WaypointFetcher_onErrorDescription() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeolocationTopComponent.WaypointFetcher.onErrorDescription");
    }
    /**
     * @return <i>Error gathering GPS Track Data</i>
     * @see GeolocationTopComponent
     */
    static String GeolocationTopComponent_WaypointFetcher_onErrorTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GeolocationTopComponent.WaypointFetcher.onErrorTitle");
    }
    /**
     * @return <i>Filters</i>
     * @see HidingPane
     */
    static String HidingPane_default_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HidingPane_default_title");
    }
    /**
     * @return <i>Failed to connect to new geolocation map tile source.</i>
     * @see MapPanel
     */
    static String MapPanel_connection_failure_message() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MapPanel_connection_failure_message");
    }
    /**
     * @return <i>Connection Failure</i>
     * @see MapPanel
     */
    static String MapPanel_connection_failure_message_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MapPanel_connection_failure_message_title");
    }
    /**
     * @return <i>Open in ExternalViewer</i>
     * @see MapWaypoint
     */
    static String MayWaypoint_ExternalViewer_label() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "MayWaypoint_ExternalViewer_label");
    }
    /**
     * @return <i>Extract Files(s)</i>
     * @see MapWaypoint
     */
    static String WaypointExtractAction_label() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "WaypointExtractAction_label");
    }
    private Bundle() {}
}
