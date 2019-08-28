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
final class ExtractSru extends Extract {

    private static final Logger logger = Logger.getLogger(ExtractSru.class.getName());
    
    private IngestJobContext context;

    private static final String SRU_TOOL_FOLDER = "markmckinnon"; //NON-NLS
    private static final String SRU_TOOL_NAME_WINDOWS = "export_srudb.exe"; //NON-NLS
    private static final String SRU_OUTPUT_FILE_NAME = "Output.txt"; //NON-NLS
    private static final String SRU_ERROR_FILE_NAME = "Error.txt"; //NON-NLS

    @Messages({
        "ExtractSru_module_name=System Resource Usage Extractor"
    })
    ExtractSru() {
        this.moduleName = Bundle.ExtractSru_module_name();
    }

    @Override
    void process(Content dataSource, IngestJobContext context, DataSourceIngestModuleProgress progressBar) {
        
        this.context = context;
        
        FileManager fileManager = Case.getCurrentCase().getServices().getFileManager();
        String tempDirPath = RAImageIngestModule.getRATempPath(Case.getCurrentCase(), "sru"); //NON-NLS
        String tempOutPath = Case.getCurrentCase().getModuleDirectory() + File.separator + "sru"; //NON-NLS

        File dir = new File(tempOutPath);
        if (dir.exists() == false) {
            dir.mkdirs();
        }

        SleuthkitCase skCase = Case.getCurrentCase().getSleuthkitCase();

        List<AbstractFile> iFiles;

        try {
            iFiles = fileManager.findFiles(dataSource, "SRUDB.DAT"); //NON-NLS            
        } catch (TskCoreException ex) {
            logger.log(Level.WARNING, "Unable to find SRUDB.DAT file.", ex); //NON-NLS
            return;  // No need to continue
        }

        for (AbstractFile iFile : iFiles) {

            if (context.dataSourceIngestIsCancelled()) {
                return;
            }

            String tempFilePath = tempDirPath + File.separator + iFile.getId() + "_" + iFile.getName();
            String tempOutFile = tempDirPath + File.separator + iFile.getId() + "_srudb.db3";

            try {
                ContentUtils.writeToFile(iFile, new File(tempFilePath));
            } catch (IOException ex) {
                logger.log(Level.WARNING, String.format("Unable to write %s to temp directory. File name: %s", iFile.getName(), tempFilePath), ex); //NON-NLS
            }

        }

        final String sruDumper = getPathForSruDumper();
        if (sruDumper == null) {
//            this.addErrorMessage(Bundle.ExtractEdge_process_errMsg_unableFindESEViewer());
            logger.log(Level.SEVERE, "Error finding export_srudb program"); //NON-NLS
            return; //If we cannot find the ESEDatabaseView we cannot proceed
        }

        if (context.dataSourceIngestIsCancelled()) {
            return;
        }

        try {
            extractSruFiles(sruDumper, tempDirPath, tempOutPath);
        } finally {
            return;
        }
//        (new File(tempDirPath)).delete();
    }

    /**
     * Run the export srudb program against the srudb.dat file
     *
     * @param sruExePath
     * @param tempDirPath
     * @param tempOutPath
     *
     * @throws FileNotFoundException
     * @throws IOException
     */
    void extractSruFiles(String sruExePath, String tempDirPath, String tempOutPath) throws FileNotFoundException, IOException {
        final Path outputFilePath = Paths.get(tempOutPath, SRU_OUTPUT_FILE_NAME);
        final Path errFilePath = Paths.get(tempOutPath, SRU_ERROR_FILE_NAME);

        
        List<String> commandLine = new ArrayList<>();
        commandLine.add(sruExePath);
        commandLine.add(tempDirPath);  //NON-NLS
        commandLine.add(tempOutPath);

        ProcessBuilder processBuilder = new ProcessBuilder(commandLine);
        processBuilder.redirectOutput(outputFilePath.toFile());
        processBuilder.redirectError(errFilePath.toFile());

        ExecUtil.execute(processBuilder, new DataSourceIngestModuleProcessTerminator(context));
    }

    private String getPathForSruDumper() {
        Path path = Paths.get(SRU_TOOL_FOLDER, SRU_TOOL_NAME_WINDOWS);
        File sruToolFile = InstalledFileLocator.getDefault().locate(path.toString(),
                ExtractSru.class.getPackage().getName(), false);
        if (sruToolFile != null) {
            return sruToolFile.getAbsolutePath();
        }

        return null;
    }

}
