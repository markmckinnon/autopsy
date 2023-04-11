package org.sleuthkit.autopsy.report.modules.kml;
/** Localizable strings for {@link org.sleuthkit.autopsy.report.modules.kml}. */
class Bundle {
    /**
     * @return <i>Could not extract Bookmark information.</i>
     * @see KMLReport
     */
    static String KMLReport_bookmarkError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "KMLReport.bookmarkError");
    }
    /**
     * @param filePath filePath
     * @return <i>Error adding </i>{@code filePath}<i> to case as a report.</i>
     * @see KMLReport
     */
    static String KMLReport_errorGeneratingReport(Object filePath) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "KMLReport.errorGeneratingReport", filePath);
    }
    /**
     * @return <i>Could not extract photos with EXIF metadata.</i>
     * @see KMLReport
     */
    static String KMLReport_exifPhotoError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "KMLReport.exifPhotoError");
    }
    /**
     * @return <i>Failed to complete report.</i>
     * @see KMLReport
     */
    static String KMLReport_failedToCompleteReport() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "KMLReport.failedToCompleteReport");
    }
    /**
     * @return <i>Could not get GPS Bookmarks from database.</i>
     * @see KMLReport
     */
    static String KMLReport_gpsBookmarkError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "KMLReport.gpsBookmarkError");
    }
    /**
     * @return <i>Could not get GPS Routes from database.</i>
     * @see KMLReport
     */
    static String KMLReport_gpsRouteDatabaseError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "KMLReport.gpsRouteDatabaseError");
    }
    /**
     * @return <i>Could not extract GPS Route information.</i>
     * @see KMLReport
     */
    static String KMLReport_gpsRouteError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "KMLReport.gpsRouteError");
    }
    /**
     * @return <i>Could not get GPS Searches from database.</i>
     * @see KMLReport
     */
    static String KMLReport_gpsSearchDatabaseError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "KMLReport.gpsSearchDatabaseError");
    }
    /**
     * @return <i>Could not write the KML file.</i>
     * @see KMLReport
     */
    static String KMLReport_kmlFileWriteError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "KMLReport.kmlFileWriteError");
    }
    /**
     * @return <i>Could not get GPS Last Known Location from database.</i>
     * @see KMLReport
     */
    static String KMLReport_locationDatabaseError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "KMLReport.locationDatabaseError");
    }
    /**
     * @return <i>Could not extract Last Known Location information.</i>
     * @see KMLReport
     */
    static String KMLReport_locationError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "KMLReport.locationError");
    }
    /**
     * @return <i>There was an error creating the report.  Some items were not exported.</i>
     * @see KMLReport
     */
    static String KMLReport_partialFailure() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "KMLReport.partialFailure");
    }
    /**
     * @return <i>Error placing KML stylesheet. The .KML file will not function properly.</i>
     * @see KMLReport
     */
    static String KMLReport_stylesheetError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "KMLReport.stylesheetError");
    }
    /**
     * @return <i>Could not get GPS Trackpoints from database.</i>
     * @see KMLReport
     */
    static String KMLReport_trackpointDatabaseError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "KMLReport.trackpointDatabaseError");
    }
    /**
     * @return <i>Could not extract Trackpoint information.</i>
     * @see KMLReport
     */
    static String KMLReport_trackpointError() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "KMLReport.trackpointError");
    }
    /**
     * @return <i>Could not extract photo information.</i>
     * @see KMLReport
     */
    static String KMLReport_unableToExtractPhotos() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "KMLReport.unableToExtractPhotos");
    }
    /**
     * @return <i>Exception while getting open case.</i>
     * @see KMLReport
     */
    static String KMLReport_unableToOpenCase() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "KMLReport.unableToOpenCase");
    }
    /**
     * @return <i>Ingest Warning message</i>
     * @see KMLReport
     */
    static String ReportBodyFile_ingestWarning_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "ReportBodyFile.ingestWarning.text");
    }
    /**
     * @return <i>GPS Route</i>
     * @see KMLReport
     */
    static String Route_Details_Header() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Route_Details_Header");
    }
    /**
     * @return <i>GPS Area Outline Point</i>
     * @see KMLReport
     */
    static String Waypoint_Area_Point_Display_String() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Waypoint_Area_Point_Display_String");
    }
    /**
     * @return <i>GPS Bookmark</i>
     * @see KMLReport
     */
    static String Waypoint_Bookmark_Display_String() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Waypoint_Bookmark_Display_String");
    }
    /**
     * @return <i>EXIF Metadata With Location</i>
     * @see KMLReport
     */
    static String Waypoint_EXIF_Display_String() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Waypoint_EXIF_Display_String");
    }
    /**
     * @return <i>GPS Last Known Location</i>
     * @see KMLReport
     */
    static String Waypoint_Last_Known_Display_String() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Waypoint_Last_Known_Display_String");
    }
    /**
     * @return <i>GPS Individual Route Point</i>
     * @see KMLReport
     */
    static String Waypoint_Route_Point_Display_String() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Waypoint_Route_Point_Display_String");
    }
    /**
     * @return <i>GPS Search</i>
     * @see KMLReport
     */
    static String Waypoint_Search_Display_String() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Waypoint_Search_Display_String");
    }
    /**
     * @return <i>GPS Track</i>
     * @see KMLReport
     */
    static String Waypoint_Track_Display_String() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Waypoint_Track_Display_String");
    }
    /**
     * @return <i>GPS Individual Track Point</i>
     * @see KMLReport
     */
    static String Waypoint_Track_Point_Display_String() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Waypoint_Track_Point_Display_String");
    }
    /**
     * @return <i>GPS Trackpoint</i>
     * @see KMLReport
     */
    static String Waypoint_Trackpoint_Display_String() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Waypoint_Trackpoint_Display_String");
    }
    private Bundle() {}
}
