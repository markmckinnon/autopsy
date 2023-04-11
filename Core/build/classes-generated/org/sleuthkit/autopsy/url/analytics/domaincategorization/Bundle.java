package org.sleuthkit.autopsy.url.analytics.domaincategorization;
/** Localizable strings for {@link org.sleuthkit.autopsy.url.analytics.domaincategorization}. */
class Bundle {
    /**
     * @return <i>Add Entry</i>
     * @see AddEditCategoryDialog
     */
    static String AddEditCategoryDialog_Add() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddEditCategoryDialog_Add");
    }
    /**
     * @return <i>Edit Entry</i>
     * @see AddEditCategoryDialog
     */
    static String AddEditCategoryDialog_Edit() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddEditCategoryDialog_Edit");
    }
    /**
     * @param maxCategoryLen maxCategoryLen
     * @return <i>Please provide a category that is no more than </i>{@code maxCategoryLen}<i> characters.</i>
     * @see AddEditCategoryDialog
     */
    static String AddEditCategoryDialog_onValueUpdate_badCategory(Object maxCategoryLen) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddEditCategoryDialog_onValueUpdate_badCategory", maxCategoryLen);
    }
    /**
     * @param maxSuffixLen maxSuffixLen
     * @return <i>Please provide a domain suffix that is no more than </i>{@code maxSuffixLen}<i> characters that includes at least one period.</i>
     * @see AddEditCategoryDialog
     */
    static String AddEditCategoryDialog_onValueUpdate_badSuffix(Object maxSuffixLen) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddEditCategoryDialog_onValueUpdate_badSuffix", maxSuffixLen);
    }
    /**
     * @return <i>Please provide a new category for this domain suffix.</i>
     * @see AddEditCategoryDialog
     */
    static String AddEditCategoryDialog_onValueUpdate_sameCategory() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddEditCategoryDialog_onValueUpdate_sameCategory");
    }
    /**
     * @return <i>Please provide a unique domain suffix.</i>
     * @see AddEditCategoryDialog
     */
    static String AddEditCategoryDialog_onValueUpdate_suffixRepeat() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddEditCategoryDialog_onValueUpdate_suffixRepeat");
    }
    /**
     * @return <i>Category</i>
     * @see WebCategoriesOptionsPanel
     */
    static String WebCategoriesOptionsPanel_categoryTable_categoryColumnName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "WebCategoriesOptionsPanel_categoryTable_categoryColumnName");
    }
    /**
     * @return <i>Domain Suffix</i>
     * @see WebCategoriesOptionsPanel
     */
    static String WebCategoriesOptionsPanel_categoryTable_suffixColumnName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "WebCategoriesOptionsPanel_categoryTable_suffixColumnName");
    }
    /**
     * @return <i>Custom Categories Export</i>
     * @see WebCategoriesOptionsPanel
     */
    static String WebCategoriesOptionsPanel_exportSetButtonActionPerformed_defaultFileName() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "WebCategoriesOptionsPanel_exportSetButtonActionPerformed_defaultFileName");
    }
    /**
     * @return <i>A file already exists at the selected path.  The categories will not be exported.</i>
     * @see WebCategoriesOptionsPanel
     */
    static String WebCategoriesOptionsPanel_exportSetButtonActionPerformed_duplicateMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "WebCategoriesOptionsPanel_exportSetButtonActionPerformed_duplicateMessage");
    }
    /**
     * @return <i>File Already Exists</i>
     * @see WebCategoriesOptionsPanel
     */
    static String WebCategoriesOptionsPanel_exportSetButtonActionPerformed_duplicateTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "WebCategoriesOptionsPanel_exportSetButtonActionPerformed_duplicateTitle");
    }
    /**
     * @return <i>There was an error exporting.</i>
     * @see WebCategoriesOptionsPanel
     */
    static String WebCategoriesOptionsPanel_exportSetButtonActionPerformed_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "WebCategoriesOptionsPanel_exportSetButtonActionPerformed_errorMessage");
    }
    /**
     * @return <i>Export Error</i>
     * @see WebCategoriesOptionsPanel
     */
    static String WebCategoriesOptionsPanel_exportSetButtonActionPerformed_errorTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "WebCategoriesOptionsPanel_exportSetButtonActionPerformed_errorTitle");
    }
    /**
     * @return <i>There was an error importing this json file.</i>
     * @see WebCategoriesOptionsPanel
     */
    static String WebCategoriesOptionsPanel_importSetButtonActionPerformed_errorMessage() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "WebCategoriesOptionsPanel_importSetButtonActionPerformed_errorMessage");
    }
    /**
     * @return <i>Import Error</i>
     * @see WebCategoriesOptionsPanel
     */
    static String WebCategoriesOptionsPanel_importSetButtonActionPerformed_errorTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "WebCategoriesOptionsPanel_importSetButtonActionPerformed_errorTitle");
    }
    /**
     * @return <i>Cancel</i>
     * @see WebCategoriesOptionsPanel
     */
    static String WebCategoriesOptionsPanel_importSetButtonActionPerformed_onConflictCancel() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "WebCategoriesOptionsPanel_importSetButtonActionPerformed_onConflictCancel");
    }
    /**
     * @param domainSuffix domainSuffix
     * @return <i>Domain suffix </i>{@code domainSuffix}<i> already exists. What would you like to do?</i>
     * @see WebCategoriesOptionsPanel
     */
    static String WebCategoriesOptionsPanel_importSetButtonActionPerformed_onConflictMessage(Object domainSuffix) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "WebCategoriesOptionsPanel_importSetButtonActionPerformed_onConflictMessage", domainSuffix);
    }
    /**
     * @return <i>Overwrite</i>
     * @see WebCategoriesOptionsPanel
     */
    static String WebCategoriesOptionsPanel_importSetButtonActionPerformed_onConflictOverwrite() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "WebCategoriesOptionsPanel_importSetButtonActionPerformed_onConflictOverwrite");
    }
    /**
     * @return <i>Skip</i>
     * @see WebCategoriesOptionsPanel
     */
    static String WebCategoriesOptionsPanel_importSetButtonActionPerformed_onConflictSkip() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "WebCategoriesOptionsPanel_importSetButtonActionPerformed_onConflictSkip");
    }
    /**
     * @return <i>Domain Suffix Already Exists</i>
     * @see WebCategoriesOptionsPanel
     */
    static String WebCategoriesOptionsPanel_importSetButtonActionPerformed_onConflictTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "WebCategoriesOptionsPanel_importSetButtonActionPerformed_onConflictTitle");
    }
    private Bundle() {}
}
