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
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import org.openide.modules.InstalledFileLocator;
import org.openide.util.NbBundle.Messages;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.autopsy.coreutils.ExecUtil;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.SQLiteDBConnect;
import org.sleuthkit.autopsy.datamodel.ContentUtils;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProcessTerminator;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.BlackboardArtifact;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_TL_EVENT;
import org.sleuthkit.datamodel.BlackboardAttribute;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.TskDataException;

/**
 * Extract the EVTX Event logs to individual SQLite databases to be used by a
 * content viewer
 */
final class ExtractSru extends Extract {

    private static final Logger logger = Logger.getLogger(ExtractSru.class.getName());

    private IngestJobContext context;

    private static final String APPLICATION_EXECUTION_ARTIFACT_NAME = "TSK_APPLICATION_EXECUTION"; //NON-NLS
    private static final String NETWORK_USAGE_ARTIFACT_NAME = "TSK_SRU_NETWORK_USAGE_BIN"; //NON-NLS
    private static final String APPLICATION_RESOURCE_ARTIFACT_NAME = "TSK_SRU_APPLICATION_RESOURCE"; //NON-NLS

    private static final String ARTIFACT_ATTRIBUTE_NAME = "TSK_ARTIFACT_NAME"; //NON-NLS
    private static final String BACKGROUND_CYCLE_TIME_ART_NAME = "TSK_BACKGROUND_CYCLE_TIME"; //NON-NLS
    private static final String FOREGROUND_CYCLE_TIME_ART_NAME = "TSK_FOREGROUND_CYCLE_TIME"; //NON-NLS
    private static final String BYTES_SENT_ART_NAME = "TSK_BYTES_SENT"; //NON-NLS
    private static final String BYTES_RECEIVED_ART_NAME = "TSK_BYTES_RECEIVED"; //NON-NLS

    private static final String MODULE_NAME = "extractSRU"; //NON-NLS

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

        try {
            createSruArtifactType();
        } catch (TskCoreException ex) {
            logger.log(Level.WARNING, String.format("%s, %s or $s may not have been created.", APPLICATION_EXECUTION_ARTIFACT_NAME, NETWORK_USAGE_ARTIFACT_NAME, APPLICATION_RESOURCE_ARTIFACT_NAME), ex);
        }

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

        String sruFile = null;
        String tempOutFile = null;
        AbstractFile sruAbstractFile = null;

        for (AbstractFile iFile : iFiles) {

            if (context.dataSourceIngestIsCancelled()) {
                return;
            }

            sruFile = tempDirPath + File.separator + iFile.getId() + "_" + iFile.getName();
            tempOutFile = tempDirPath + File.separator + iFile.getId() + "_srudb.db3";
            sruAbstractFile = iFile;

            try {
                ContentUtils.writeToFile(iFile, new File(sruFile));
            } catch (IOException ex) {
                logger.log(Level.WARNING, String.format("Unable to write %s to temp directory. File name: %s", iFile.getName(), sruFile), ex); //NON-NLS
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
        if (sruFile == null) {
//            this.addErrorMessage(Bundle.ExtractEdge_process_errMsg_unableFindESEViewer());
            logger.log(Level.SEVERE, "SRUDB.dat file not found"); //NON-NLS
            return; //If we cannot find the ESEDatabaseView we cannot proceed
        }

        try {
            extractSruFiles(sruDumper, sruFile, tempOutFile, tempDirPath);
            createSruAttributeType();
            createSruArtifactType();
            createAppExecArtifacts(tempOutFile, sruAbstractFile);
            createNetUsageArtifacts(tempOutFile, sruAbstractFile);
            createAppUsageArtifacts(tempOutFile, sruAbstractFile);
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
    void extractSruFiles(String sruExePath, String sruFile, String tempOutFile, String tempOutPath) throws FileNotFoundException, IOException {
        final Path outputFilePath = Paths.get(tempOutPath, SRU_OUTPUT_FILE_NAME);
        final Path errFilePath = Paths.get(tempOutPath, SRU_ERROR_FILE_NAME);

        List<String> commandLine = new ArrayList<>();
        commandLine.add(sruExePath);
        commandLine.add(sruFile);  //NON-NLS
        commandLine.add(tempOutFile);

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

    private void createAppExecArtifacts(String sruDb, AbstractFile sruAbstractFile) {
        Blackboard blackboard = currentCase.getSleuthkitCase().getBlackboard();
        BlackboardAttribute.Type artifactAttributeType;
        BlackboardArtifact.Type artifactType;
        try {
            artifactAttributeType = currentCase.getSleuthkitCase().getAttributeType(ARTIFACT_ATTRIBUTE_NAME);
            artifactType = currentCase.getSleuthkitCase().getArtifactType(APPLICATION_EXECUTION_ARTIFACT_NAME);
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, String.format("Error Finding Attribute %s Artifact.", ARTIFACT_ATTRIBUTE_NAME), ex);//NON-NLS
            return;
        }

        Content sruContentFile = sruAbstractFile;

//        String sqlStatement = "select strftime('%s', ExecutionTime) ExecutionTime, ApplicationName, TableName from application_execution;"; //NON-NLS
        String sqlStatement = "SELECT DISTINCT ApplicationName, TableName FROM application_execution;"; //NON-NLS

        try (SQLiteDBConnect tempdbconnect = new SQLiteDBConnect("org.sqlite.JDBC", "jdbc:sqlite:" + sruDb); //NON-NLS
                ResultSet resultSet = tempdbconnect.executeQry(sqlStatement)) {

            while (resultSet.next()) {

                if (context.dataSourceIngestIsCancelled()) {
                    logger.log(Level.INFO, "Cancelled SRU Artifact Creation."); //NON-NLS
                    return;
                }

//                int executionTime = resultSet.getInt("ExecutionTime"); //NON-NLS
                String applicationName = resultSet.getString("ApplicationName"); //NON-NLS
                String artifactName = resultSet.getString("TableName"); //NON-NLS

                Collection<BlackboardAttribute> bbattributes = Arrays.asList(
                        //                        new BlackboardAttribute(
                        //                                TSK_DATETIME, getName(),
                        //                                executionTime), //NON-NLS
                        new BlackboardAttribute(
                                TSK_PROG_NAME, getName(),
                                applicationName),//NON-NLS
                        new BlackboardAttribute(
                                artifactAttributeType, getName(),
                                artifactName));

                try {
                    BlackboardArtifact bbart = sruContentFile.newArtifact(artifactType.getTypeID());
                    bbart.addAttributes(bbattributes);
                    try {
                        /*
                         * Post the artifact which will index the artifact for
                         * keyword search, and fire an event to notify UI of
                         * this new artifact
                         */
                        blackboard.postArtifact(bbart, MODULE_NAME);
                    } catch (Blackboard.BlackboardException ex) {
                        logger.log(Level.SEVERE, "Error Posting Artifact.", ex);//NON-NLS
                    }
                } catch (TskCoreException ex) {
                    logger.log(Level.SEVERE, "Exception Adding Artifact.", ex);//NON-NLS
                }
            }

        } catch (SQLException ex) {
            logger.log(Level.SEVERE, "Error while trying to read into a sqlite db.", ex);//NON-NLS
        }
    }
 
    private void createNetUsageArtifacts(String sruDb, AbstractFile sruAbstractFile) {
        Blackboard blackboard = currentCase.getSleuthkitCase().getBlackboard();
        BlackboardAttribute.Type bytesSentAttributeType;
        BlackboardAttribute.Type bytesRecvAttributeType;
        BlackboardArtifact.Type artifactType;

        try {
            bytesSentAttributeType = currentCase.getSleuthkitCase().getAttributeType(BYTES_SENT_ART_NAME);
            bytesRecvAttributeType = currentCase.getSleuthkitCase().getAttributeType(BYTES_RECEIVED_ART_NAME);
            artifactType = currentCase.getSleuthkitCase().getArtifactType(NETWORK_USAGE_ARTIFACT_NAME);
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Error getting Net Usage Attribute's and Artifact.", ex);//NON-NLS
            return;
        }

        Content sruContentFile = sruAbstractFile;

        String sqlStatement = "SELECT STRFTIME('%s', timestamp) ExecutionTime, idBlob ApplicationName, "
                + " bytesSent, BytesRecvd FROM network_Usage, SruDbIdMapTable WHERE appid = idIndex;"; //NON-NLS

        try (SQLiteDBConnect tempdbconnect = new SQLiteDBConnect("org.sqlite.JDBC", "jdbc:sqlite:" + sruDb); //NON-NLS
                ResultSet resultSet = tempdbconnect.executeQry(sqlStatement)) {

            while (resultSet.next()) {

                if (context.dataSourceIngestIsCancelled()) {
                    logger.log(Level.INFO, "Cancelled SRU Net Usage Artifact Creation."); //NON-NLS
                    return;
                }

//                int executionTime = resultSet.getInt("ExecutionTime"); //NON-NLS
                String applicationName = resultSet.getString("ApplicationName"); //NON-NLS
                Long executionTime = new Long(resultSet.getInt("ExecutionTime")); //NON-NLS
                Long bytesSent = new Long(resultSet.getInt("bytesSent")); //NON-NLS
                Long bytesRecvd = new Long(resultSet.getInt("BytesRecvd")); //NON-NLS

                Collection<BlackboardAttribute> bbattributes = Arrays.asList(
                        new BlackboardAttribute(
                                TSK_PROG_NAME, getName(),
                                applicationName),//NON-NLS
                        new BlackboardAttribute(
                                TSK_DATETIME, getName(),
                                executionTime),
                        new BlackboardAttribute(
                                bytesSentAttributeType, getName(),
                                bytesSent),
                        new BlackboardAttribute(
                                bytesRecvAttributeType, getName(),
                                bytesRecvd));

                try {
                    BlackboardArtifact bbart = sruContentFile.newArtifact(artifactType.getTypeID());
                    bbart.addAttributes(bbattributes);
                    try {
                        /*
                         * Post the artifact which will index the artifact for
                         * keyword search, and fire an event to notify UI of
                         * this new artifact
                         */
                        blackboard.postArtifact(bbart, MODULE_NAME);
                    } catch (Blackboard.BlackboardException ex) {
                        logger.log(Level.SEVERE, "Error Posting Artifact.", ex);//NON-NLS
                    }
                } catch (TskCoreException ex) {
                    logger.log(Level.SEVERE, "Exception Adding Artifact.", ex);//NON-NLS
                }
            }

        } catch (SQLException ex) {
            logger.log(Level.SEVERE, "Error while trying to read into a sqlite db.", ex);//NON-NLS
        }
    }

    private void createAppUsageArtifacts(String sruDb, AbstractFile sruAbstractFile) {
        Blackboard blackboard = currentCase.getSleuthkitCase().getBlackboard();
        BlackboardAttribute.Type fgCycleTimeAttributeType;
        BlackboardAttribute.Type bgCycleTimeAttributeType;
        BlackboardArtifact.Type artifactType;

        try {
            fgCycleTimeAttributeType = currentCase.getSleuthkitCase().getAttributeType(FOREGROUND_CYCLE_TIME_ART_NAME);
            bgCycleTimeAttributeType = currentCase.getSleuthkitCase().getAttributeType(BACKGROUND_CYCLE_TIME_ART_NAME);
            artifactType = currentCase.getSleuthkitCase().getArtifactType(APPLICATION_RESOURCE_ARTIFACT_NAME);
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Error getting APP Usage Attribute's and Artifact.", ex);//NON-NLS
            return;
        }

        Content sruContentFile = sruAbstractFile;

        String sqlStatement = "SELECT STRFTIME('%s', timestamp) ExecutionTime, idBlob ApplicationName, "
                + " foregroundCycleTime, backgroundCycleTime FROM Application_Resource_Usage, SruDbIdMapTable WHERE appid = idIndex;"; //NON-NLS

        try (SQLiteDBConnect tempdbconnect = new SQLiteDBConnect("org.sqlite.JDBC", "jdbc:sqlite:" + sruDb); //NON-NLS
                ResultSet resultSet = tempdbconnect.executeQry(sqlStatement)) {

            while (resultSet.next()) {

                if (context.dataSourceIngestIsCancelled()) {
                    logger.log(Level.INFO, "Cancelled SRU Net Usage Artifact Creation."); //NON-NLS
                    return;
                }

//                int executionTime = resultSet.getInt("ExecutionTime"); //NON-NLS
                String applicationName = resultSet.getString("ApplicationName"); //NON-NLS
                Long executionTime = new Long(resultSet.getInt("ExecutionTime")); //NON-NLS
                Long fgCycleTime = new Long(resultSet.getInt("foregroundCycleTime")); //NON-NLS
                Long bgCycleTime = new Long(resultSet.getInt("backgroundCycleTime")); //NON-NLS

                Collection<BlackboardAttribute> bbattributes = Arrays.asList(
                        new BlackboardAttribute(
                                TSK_PROG_NAME, getName(),
                                applicationName),//NON-NLS
                        new BlackboardAttribute(
                                TSK_DATETIME, getName(),
                                executionTime),
                        new BlackboardAttribute(
                                fgCycleTimeAttributeType, getName(),
                                fgCycleTime),
                        new BlackboardAttribute(
                                bgCycleTimeAttributeType, getName(),
                                bgCycleTime));

                try {
                    BlackboardArtifact bbart = sruContentFile.newArtifact(artifactType.getTypeID());
                    bbart.addAttributes(bbattributes);
                    try {
                        /*
                         * Post the artifact which will index the artifact for
                         * keyword search, and fire an event to notify UI of
                         * this new artifact
                         */
                        blackboard.postArtifact(bbart, MODULE_NAME);
                    } catch (Blackboard.BlackboardException ex) {
                        logger.log(Level.SEVERE, "Error Posting Artifact.", ex);//NON-NLS
                    }
                } catch (TskCoreException ex) {
                    logger.log(Level.SEVERE, "Exception Adding Artifact.", ex);//NON-NLS
                }
            }

        } catch (SQLException ex) {
            logger.log(Level.SEVERE, "Error while trying to read into a sqlite db.", ex);//NON-NLS
        }
    }

    /**
     * Create artifact type's for System Resource Usage.
     *
     * @throws TskCoreException
     */
    private void createSruArtifactType() throws TskCoreException {

        try {
            tskCase.addBlackboardArtifactType(APPLICATION_EXECUTION_ARTIFACT_NAME, "Application Execution"); //NON-NLS
        } catch (TskDataException ex) {
            logger.log(Level.INFO, String.format("%s may have already been defined for this case", APPLICATION_EXECUTION_ARTIFACT_NAME));
        }
        try {
            tskCase.addBlackboardArtifactType(NETWORK_USAGE_ARTIFACT_NAME, "SRU Network Usage"); //NON-NLS
        } catch (TskDataException ex) {
            logger.log(Level.INFO, String.format("%s may have already been defined for this case", NETWORK_USAGE_ARTIFACT_NAME));
        }
        try {
            tskCase.addBlackboardArtifactType(APPLICATION_RESOURCE_ARTIFACT_NAME, "SRU Application Resource Usage"); //NON-NLS
        } catch (TskDataException ex) {
            logger.log(Level.INFO, String.format("%s may have already been defined for this case", APPLICATION_RESOURCE_ARTIFACT_NAME));
        }

    }

    /**
     * Create System Resource Usage Attribute type's.
     *
     * @throws TskCoreException
     */
    private void createSruAttributeType() throws TskCoreException {

        try {
            tskCase.addArtifactAttributeType(ARTIFACT_ATTRIBUTE_NAME, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Artifact Name"); //NON-NLS
        } catch (TskDataException ex) {
            logger.log(Level.INFO, String.format("%s may have already been defined for this case", ARTIFACT_ATTRIBUTE_NAME));
        }
        try {
            tskCase.addArtifactAttributeType(BACKGROUND_CYCLE_TIME_ART_NAME, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "Background Cycle Time"); //NON-NLS
        } catch (TskDataException ex) {
            logger.log(Level.INFO, String.format("%s may have already been defined for this case", BACKGROUND_CYCLE_TIME_ART_NAME));
        }
        try {
            tskCase.addArtifactAttributeType(FOREGROUND_CYCLE_TIME_ART_NAME, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "Foreground Cycle Time"); //NON-NLS
        } catch (TskDataException ex) {
            logger.log(Level.INFO, String.format("%s may have already been defined for this case", FOREGROUND_CYCLE_TIME_ART_NAME));
        }
        try {
            tskCase.addArtifactAttributeType(BYTES_SENT_ART_NAME, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "Bytes Sent"); //NON-NLS
        } catch (TskDataException ex) {
            logger.log(Level.INFO, String.format("%s may have already been defined for this case", BYTES_SENT_ART_NAME));
        }
        try {
            tskCase.addArtifactAttributeType(BYTES_RECEIVED_ART_NAME, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "Bytes Received"); //NON-NLS
        } catch (TskDataException ex) {
            logger.log(Level.INFO, String.format("%s may have already been defined for this case", BYTES_RECEIVED_ART_NAME));
        }

    }

}
