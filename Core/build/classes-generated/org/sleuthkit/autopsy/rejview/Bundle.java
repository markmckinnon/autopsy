package org.sleuthkit.autopsy.rejview;
/** Localizable strings for {@link org.sleuthkit.autopsy.rejview}. */
class Bundle {
    /**
     * @param startByteD startByteD
     * @param endByteD endByteD
     * @param lengthD lengthD
     * @param startByteH startByteH
     * @param endByteH endByteH
     * @param lengthH lengthH
     * @return <i>Selection: </i>{@code startByteD}<i> to </i>{@code endByteD}<i> (len: </i>{@code lengthD}<i>) [</i>{@code startByteH}<i> to </i>{@code endByteH}<i> (len: </i>{@code lengthH}<i>)</i>
     * @see HexView
     */
    static String HexView_statusTemplate_nonZeroLength(Object startByteD, Object endByteD, Object lengthD, Object startByteH, Object endByteH, Object lengthH) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HexView.statusTemplate.nonZeroLength", startByteD, endByteD, lengthD, startByteH, endByteH, lengthH);
    }
    /**
     * @param startByteDec startByteDec
     * @param startByteHex startByteHex
     * @return <i>Position: </i>{@code startByteDec}<i> [</i>{@code startByteHex}<i>])</i>
     * @see HexView
     */
    static String HexView_statusTemplate_zeroLength(Object startByteDec, Object startByteHex) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "HexView.statusTemplate.zeroLength", startByteDec, startByteHex);
    }
    /**
     * @return <i>(value not set)</i>
     * @see RegeditExeValueFormatter
     */
    static String RegeditExeValueFormatter_valueNotSet_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RegeditExeValueFormatter.valueNotSet.text");
    }
    /**
     * @return <i>PARSE FAILED.</i>
     * @see RejTreeKeyNode
     */
    static String RejTreeKeyNode_parseFailed_string() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejTreeKeyNode.parseFailed.string");
    }
    /**
     * @return <i>Name</i>
     * @see RejTreeKeyView
     */
    static String RejTreeKeyView_columns_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejTreeKeyView.columns.name");
    }
    /**
     * @return <i>Type</i>
     * @see RejTreeKeyView
     */
    static String RejTreeKeyView_columns_type() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejTreeKeyView.columns.type");
    }
    /**
     * @return <i>Value</i>
     * @see RejTreeKeyView
     */
    static String RejTreeKeyView_columns_value() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejTreeKeyView.columns.value");
    }
    /**
     * @return <i>FAILED TO PARSE KEY NAME</i>
     * @see RejTreeKeyView
     */
    static String RejTreeKeyView_failedToParse_keyName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejTreeKeyView.failedToParse.keyName");
    }
    /**
     * @return <i>Metadata</i>
     * @see RejTreeKeyView
     */
    static String RejTreeKeyView_metadataBorder_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejTreeKeyView.metadataBorder.title");
    }
    /**
     * @return <i>Modification Time:</i>
     * @see RejTreeKeyView
     */
    static String RejTreeKeyView_template_dateTime() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejTreeKeyView.template.dateTime");
    }
    /**
     * @return <i>Name:</i>
     * @see RejTreeKeyView
     */
    static String RejTreeKeyView_template_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejTreeKeyView.template.name");
    }
    /**
     * @return <i>Number of subkeys:</i>
     * @see RejTreeKeyView
     */
    static String RejTreeKeyView_template_numberOfSubkeys() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejTreeKeyView.template.numberOfSubkeys");
    }
    /**
     * @return <i>Number of values:</i>
     * @see RejTreeKeyView
     */
    static String RejTreeKeyView_template_numberOfValues() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejTreeKeyView.template.numberOfValues");
    }
    /**
     * @return <i>Values</i>
     * @see RejTreeKeyView
     */
    static String RejTreeKeyView_valuesBorder_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejTreeKeyView.valuesBorder.title");
    }
    /**
     * @return <i>(Default)</i>
     * @see RejTreeValueNode
     */
    static String RejTreeValueNode_defaultValueName_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejTreeValueNode.defaultValueName.text");
    }
    /**
     * @return <i>PARSE FAILED</i>
     * @see RejTreeValueNode
     */
    static String RejTreeValueNode_failureValueName_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejTreeValueNode.failureValueName.text");
    }
    /**
     * @return <i>FAILED TO DECODE VALUE NAME</i>
     * @see RejTreeValueView
     */
    static String RejTreeValueView_failedToDecode_valueName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejTreeValueView.failedToDecode.valueName");
    }
    /**
     * @return <i>FAILED TO PARSE VALUE TYPE</i>
     * @see RejTreeValueView
     */
    static String RejTreeValueView_failedToDecode_valueType() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejTreeValueView.failedToDecode.valueType");
    }
    /**
     * @return <i>FAILED TO PARSE VALUE VALUE</i>
     * @see RejTreeValueView
     */
    static String RejTreeValueView_failedToParse_value() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejTreeValueView.failedToParse.value");
    }
    /**
     * @return <i>Metadata</i>
     * @see RejTreeValueView
     */
    static String RejTreeValueView_metadataBorder_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejTreeValueView.metadataBorder.title");
    }
    /**
     * @return <i>Name:</i>
     * @see RejTreeValueView
     */
    static String RejTreeValueView_template_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejTreeValueView.template.name");
    }
    /**
     * @return <i>Type:</i>
     * @see RejTreeValueView
     */
    static String RejTreeValueView_template_type() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejTreeValueView.template.type");
    }
    /**
     * @return <i>Value</i>
     * @see RejTreeValueView
     */
    static String RejTreeValueView_valueBorder_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejTreeValueView.valueBorder.title");
    }
    /**
     * @return <i>PARSE FAILED</i>
     * @see RejTreeView
     */
    static String RejTreeView_failureValueName_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "RejTreeView.failureValueName.text");
    }
    private Bundle() {}
}
