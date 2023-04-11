package org.sleuthkit.autopsy.geolocation.datamodel;
/** Localizable strings for {@link org.sleuthkit.autopsy.geolocation.datamodel}. */
class Bundle {
    /**
     * @param area_name area name
     * @return <i>Area outline point for area: </i>{@code area_name}
     * @see Area
     */
    static String GEOArea_point_label_header(Object area_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GEOArea_point_label_header", area_name);
    }
    /**
     * @param track_name track name
     * @return <i>Trackpoint for track: </i>{@code track_name}
     * @see Track
     */
    static String GEOTrack_point_label_header(Object track_name) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "GEOTrack_point_label_header", track_name);
    }
    /**
     * @return <i>Last Known Location</i>
     * @see LastKnownWaypoint
     */
    static String LastKnownWaypoint_Label() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "LastKnownWaypoint_Label");
    }
    /**
     * @return <i>End</i>
     * @see Route
     */
    static String Route_End_Label() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Route_End_Label");
    }
    /**
     * @return <i>As-the-crow-flies Route</i>
     * @see Route
     */
    static String Route_Label() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Route_Label");
    }
    /**
     * @return <i>Start</i>
     * @see Route
     */
    static String Route_Start_Label() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Route_Start_Label");
    }
    /**
     * @return <i>Waypoints for route</i>
     * @see Route
     */
    static String Route_point_label() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Route_point_label");
    }
    /**
     * @return <i>GPS Search</i>
     * @see SearchWaypoint
     */
    static String SearchWaypoint_DisplayLabel() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "SearchWaypoint_DisplayLabel");
    }
    /**
     * @return <i>Distance from home point</i>
     * @see Track
     */
    static String Track_distanceFromHome_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Track_distanceFromHome_displayName");
    }
    /**
     * @return <i>Distance traveled</i>
     * @see Track
     */
    static String Track_distanceTraveled_displayName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "Track_distanceTraveled_displayName");
    }
    /**
     * @return <i>GPS Trackpoint</i>
     * @see TrackpointWaypoint
     */
    static String TrackpointWaypoint_DisplayLabel() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "TrackpointWaypoint_DisplayLabel");
    }
    private Bundle() {}
}
