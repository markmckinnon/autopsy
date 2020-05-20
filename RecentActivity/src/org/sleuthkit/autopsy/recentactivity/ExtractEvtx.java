/*
 *
 * Autopsy Forensic Browser
 *
 * Copyright 2019 Basis Technology Corp.
 *
 * Copyright 2012 42six Solutions.
 * Contact: aebadirad <at> 42six <dot> com
 * Project Contact/Architect: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.autopsy.recentactivity;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import org.openide.modules.InstalledFileLocator;
import org.openide.util.NbBundle.Messages;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.autopsy.coreutils.ExecUtil;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.datamodel.ContentUtils;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProcessTerminator;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;

/**
 * Extract the EVTX Event logs to individual SQLite databases to be used by a
 * content viewer
 */
final class ExtractEvtx extends Extract {

    private static final Logger logger = Logger.getLogger(ExtractEvtx.class.getName());
    
    private IngestJobContext context;

    private static final String EVTX_TOOL_FOLDER = "markmckinnon"; //NON-NLS
    private static final String EVTX_TOOL_NAME = "export_evtx.exe"; //NON-NLS
    private static final String EVTX_OUTPUT_FILE_NAME = "Output.txt"; //NON-NLS
    private static final String EVTX_ERROR_FILE_NAME = "Error.txt"; //NON-NLS

    @Messages({
        "ExtractEvtx_module_name=Event Log Extractor"
    })
    ExtractEvtx() {
        this.moduleName = Bundle.ExtractEvtx_module_name();
    }

    @Override
    void process(Content dataSource, IngestJobContext context, DataSourceIngestModuleProgress progressBar) {
        
        this.context = context;
        
        FileManager fileManager = Case.getCurrentCase().getServices().getFileManager();
        String tempDirPath = RAImageIngestModule.getRATempPath(Case.getCurrentCase(), "evtx"); //NON-NLS
        String modDirPath = Case.getCurrentCase().getModuleDirectory() + File.separator + "evtx"; //NON-NLS

        File dir = new File(modDirPath);
        if (dir.exists() == false) {
            dir.mkdirs();
        }

        SleuthkitCase skCase = Case.getCurrentCase().getSleuthkitCase();

        List<AbstractFile> eFiles;

        try {
            eFiles = fileManager.findFiles(dataSource, "%.evtx"); //NON-NLS            
        } catch (TskCoreException ex) {
            logger.log(Level.WARNING, "Unable to find Event Log evtx files.", ex); //NON-NLS
            return;  // No need to continue
        }

        for (AbstractFile eFile : eFiles) {

            if (context.dataSourceIngestIsCancelled()) {
                return;
            }

            String tempFilePath = tempDirPath + File.separator + eFile.getId() + "_" + eFile.getName();

            try {
                ContentUtils.writeToFile(eFile, new File(tempFilePath));
            } catch (IOException ex) {
                logger.log(Level.WARNING, String.format("Unable to write %s to temp directory. File name: %s", eFile.getName(), tempFilePath), ex); //NON-NLS
            }

        }

        final String evtxDumper = getPathForEvtxDumper();
        if (evtxDumper == null) {
            logger.log(Level.SEVERE, "Error finding export_evtx program"); //NON-NLS
            return; //If we cannot find the export_evtx program so we cannot proceed
        }

        if (context.dataSourceIngestIsCancelled()) {
            return;
        }

        try {
            extractEvtxFiles(evtxDumper, tempDirPath, modDirPath);
        } finally {
            return;
        }
    }

    /**
     * Run the Evtx extracting program.
     *
     * For versions of Windows prior to 10, header = 0x01. Windows 10+ header ==
     * 0x02
     *
     * @param evtxExePath path tto the evtx extractor executable.
     * @param tempDirPath path to the temp directory where the evtx files to be extracted are
     * @param modDirPath path to the module directory to store output
     *
     * @throws FileNotFoundException
     * @throws IOException
     */
    void extractEvtxFiles(String evtxExePath, String tempDirPath, String modDirPath) throws FileNotFoundException, IOException {
        final Path outputFilePath = Paths.get(modDirPath, EVTX_OUTPUT_FILE_NAME);
        final Path errFilePath = Paths.get(modDirPath, EVTX_ERROR_FILE_NAME);
        
        List<String> commandLine = new ArrayList<>();
        commandLine.add(evtxExePath);
        commandLine.add(tempDirPath);  //NON-NLS
        commandLine.add(modDirPath);

        ProcessBuilder processBuilder = new ProcessBuilder(commandLine);
        processBuilder.redirectOutput(outputFilePath.toFile());
        processBuilder.redirectError(errFilePath.toFile());

        ExecUtil.execute(processBuilder, new DataSourceIngestModuleProcessTerminator(context));
    }

    private String getPathForEvtxDumper() {
        Path path = Paths.get(EVTX_TOOL_FOLDER, EVTX_TOOL_NAME);
        File evtxToolFile = InstalledFileLocator.getDefault().locate(path.toString(),
                ExtractEvtx.class.getPackage().getName(), false);
        if (evtxToolFile != null) {
            return evtxToolFile.getAbsolutePath();
        }

        return null;
    }

}
