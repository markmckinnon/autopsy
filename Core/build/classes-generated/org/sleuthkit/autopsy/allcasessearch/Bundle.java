package org.sleuthkit.autopsy.allcasessearch;
/** Localizable strings for {@link org.sleuthkit.autopsy.allcasessearch}. */
class Bundle {
    /**
     * @return <i>Search Central Repository</i>
     * @see AllCasesSearchAction
     */
    static String AllCasesSearchAction_getName_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchAction.getName.text");
    }
    /**
     * @param number_of_cases number of cases
     * @return <i>The Central Repository contains </i>{@code number_of_cases}<i> case(s).</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_caseLabel_text(Object number_of_cases) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.caseLabel.text", number_of_cases);
    }
    /**
     * @return <i>Example: "domain.com"</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_correlationValueTextField_domainExample() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.correlationValueTextField.domainExample");
    }
    /**
     * @return <i>Example: "user&#64;host.com"</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_correlationValueTextField_emailExample() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.correlationValueTextField.emailExample");
    }
    /**
     * @return <i>Example: "f0e1d2c3b4a5968778695a4b3c2d1e0f"</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_correlationValueTextField_filesExample() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.correlationValueTextField.filesExample");
    }
    /**
     * @return <i>Example: "89 91 19 1299 99 329451 0"</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_correlationValueTextField_iccidExample() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.correlationValueTextField.iccidExample");
    }
    /**
     * @return <i>Example: "351756061523999"</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_correlationValueTextField_imeiExample() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.correlationValueTextField.imeiExample");
    }
    /**
     * @return <i>Example: "310150123456789"</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_correlationValueTextField_imsiExample() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.correlationValueTextField.imsiExample");
    }
    /**
     * @return <i>Example: "0C-14-F2-01-AF-45"</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_correlationValueTextField_macExample() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.correlationValueTextField.macExample");
    }
    /**
     * @return <i>Example: "(800)123-4567"</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_correlationValueTextField_phoneExample() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.correlationValueTextField.phoneExample");
    }
    /**
     * @return <i>Example: "WirelessNetwork-5G"</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_correlationValueTextField_ssidExample() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.correlationValueTextField.ssidExample");
    }
    /**
     * @return <i>Example: "4&amp;1234567&amp;0"</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_correlationValueTextField_usbExample() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.correlationValueTextField.usbExample");
    }
    /**
     * @return <i>Search Central Repository</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_dialogTitle_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.dialogTitle.text");
    }
    /**
     * @return <i>No results found.</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_emptyNode_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.emptyNode.text");
    }
    /**
     * @return <i>Search Central Repository</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_resultsDescription_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.resultsDescription.text");
    }
    /**
     * @return <i>All Cases</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_resultsTitle_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.resultsTitle.text");
    }
    /**
     * @return <i>The supplied value is not valid.</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_validation_genericMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.validation.genericMessage");
    }
    /**
     * @return <i>The supplied value is not a valid domain.</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_validation_invalidDomain() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.validation.invalidDomain");
    }
    /**
     * @return <i>The supplied value is not a valid e-mail address.</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_validation_invalidEmail() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.validation.invalidEmail");
    }
    /**
     * @return <i>The supplied value is not a valid MD5 hash.</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_validation_invalidHash() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.validation.invalidHash");
    }
    /**
     * @return <i>The supplied value is not a valid ICCID number.</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_validation_invalidIccid() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.validation.invalidIccid");
    }
    /**
     * @return <i>The supplied value is not a valid IMEI number.</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_validation_invalidImei() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.validation.invalidImei");
    }
    /**
     * @return <i>The supplied value is not a valid IMSI number.</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_validation_invalidImsi() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.validation.invalidImsi");
    }
    /**
     * @return <i>The supplied value is not a valid MAC address.</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_validation_invalidMac() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.validation.invalidMac");
    }
    /**
     * @return <i>The supplied value is not a valid phone number.</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_validation_invalidPhone() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.validation.invalidPhone");
    }
    /**
     * @return <i>The supplied value is not a valid wireless network.</i>
     * @see AllCasesSearchDialog
     */
    static String AllCasesSearchDialog_validation_invalidSsid() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchDialog.validation.invalidSsid");
    }
    /**
     * @return <i>Other Cases Search</i>
     * @see AllCasesSearchNode
     */
    static String AllCasesSearchNode_getName_text() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AllCasesSearchNode.getName.text");
    }
    /**
     * @return <i>Search Central Repository</i>
     * @see AllCasesSearchAction
     */
    static String CTL_AllCasesSearchAction() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CTL_AllCasesSearchAction");
    }
    /**
     * @return <i>Case</i>
     * @see CorrelationAttributeInstanceNode
     */
    static String CorrelationAttributeInstanceNode_columnName_case() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationAttributeInstanceNode.columnName.case");
    }
    /**
     * @return <i>Comment</i>
     * @see CorrelationAttributeInstanceNode
     */
    static String CorrelationAttributeInstanceNode_columnName_comment() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationAttributeInstanceNode.columnName.comment");
    }
    /**
     * @return <i>Data Source</i>
     * @see CorrelationAttributeInstanceNode
     */
    static String CorrelationAttributeInstanceNode_columnName_dataSource() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationAttributeInstanceNode.columnName.dataSource");
    }
    /**
     * @return <i>Device</i>
     * @see CorrelationAttributeInstanceNode
     */
    static String CorrelationAttributeInstanceNode_columnName_device() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationAttributeInstanceNode.columnName.device");
    }
    /**
     * @return <i>Known</i>
     * @see CorrelationAttributeInstanceNode
     */
    static String CorrelationAttributeInstanceNode_columnName_known() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationAttributeInstanceNode.columnName.known");
    }
    /**
     * @return <i>Name</i>
     * @see CorrelationAttributeInstanceNode
     */
    static String CorrelationAttributeInstanceNode_columnName_name() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationAttributeInstanceNode.columnName.name");
    }
    /**
     * @return <i>Path</i>
     * @see CorrelationAttributeInstanceNode
     */
    static String CorrelationAttributeInstanceNode_columnName_path() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationAttributeInstanceNode.columnName.path");
    }
    /**
     * @return <i>Value</i>
     * @see CorrelationAttributeInstanceNode
     */
    static String CorrelationAttributeInstanceNode_columnName_value() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "CorrelationAttributeInstanceNode.columnName.value");
    }
    private Bundle() {}
}
