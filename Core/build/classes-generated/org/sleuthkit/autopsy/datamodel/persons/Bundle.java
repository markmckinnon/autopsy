package org.sleuthkit.autopsy.datamodel.persons;
/** Localizable strings for {@link org.sleuthkit.autopsy.datamodel.persons}. */
class Bundle {
    /**
     * @return <i>Add Person</i>
     * @see AddEditPersonDialog
     */
    static String AddEditPersonDialog_addPerson_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddEditPersonDialog_addPerson_title");
    }
    /**
     * @return <i>Edit Person</i>
     * @see AddEditPersonDialog
     */
    static String AddEditPersonDialog_editPerson_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "AddEditPersonDialog_editPerson_title");
    }
    /**
     * @return <i>Delete Person</i>
     * @see DeletePersonAction
     */
    static String DeletePersonAction_menuTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DeletePersonAction_menuTitle");
    }
    /**
     * @param personName personName
     * @return <i>There was an error removing person: </i>{@code personName}<i>.</i>
     * @see DeletePersonAction
     */
    static String DeletePersonAction_onError_description(Object personName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DeletePersonAction_onError_description", personName);
    }
    /**
     * @return <i>Error Delete Host from Person</i>
     * @see DeletePersonAction
     */
    static String DeletePersonAction_onError_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "DeletePersonAction_onError_title");
    }
    /**
     * @return <i>Edit Person...</i>
     * @see EditPersonAction
     */
    static String EditPersonAction_menuTitle() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditPersonAction_menuTitle");
    }
    /**
     * @param personName personName
     * @return <i>There was an error editing person: </i>{@code personName}<i>.</i>
     * @see EditPersonAction
     */
    static String EditPersonAction_onError_description(Object personName) {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditPersonAction_onError_description", personName);
    }
    /**
     * @return <i>Error Editing Person</i>
     * @see EditPersonAction
     */
    static String EditPersonAction_onError_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "EditPersonAction_onError_title");
    }
    /**
     * @return <i>Another person already has the same name.  Please choose a different name.</i>
     * @see PersonNameValidator
     */
    static String PersonNameValidator_getValidationMessage_onDuplicate() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonNameValidator_getValidationMessage_onDuplicate");
    }
    /**
     * @return <i>Please provide some text for the person name.</i>
     * @see PersonNameValidator
     */
    static String PersonNameValidator_getValidationMessage_onEmpty() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonNameValidator_getValidationMessage_onEmpty");
    }
    /**
     * @return <i>Please provide a new name for this person.</i>
     * @see PersonNameValidator
     */
    static String PersonNameValidator_getValidationMessage_sameAsOriginal() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "PersonNameValidator_getValidationMessage_sameAsOriginal");
    }
    private Bundle() {}
}
