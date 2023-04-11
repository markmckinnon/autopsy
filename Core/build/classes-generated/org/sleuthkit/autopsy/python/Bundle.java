package org.sleuthkit.autopsy.python;
/** Localizable strings for {@link org.sleuthkit.autopsy.python}. */
class Bundle {
    /**
     * @return <i>Failed to load python modules, See log for more details</i>
     * @see JythonModuleLoader
     */
    static String JythonModuleLoader_pythonInterpreterError_msg() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "JythonModuleLoader.pythonInterpreterError.msg");
    }
    /**
     * @return <i>Python Modules</i>
     * @see JythonModuleLoader
     */
    static String JythonModuleLoader_pythonInterpreterError_title() {
        return org.openide.util.NbBundle.getMessage(Bundle.class, "JythonModuleLoader.pythonInterpreterError.title");
    }
    private Bundle() {}
}
