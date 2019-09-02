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
final class ExtractPrefetch extends Extract {

    private static final Logger logger = Logger.getLogger(ExtractPrefetch.class.getName());

    private IngestJobContext context;

    private static final String APPLICATION_EXECUTION_ARTIFACT_NAME = "TSK_APPLICATION_EXECUTION"; //NON-NLS
    private static final String PREFETCH_ARTIFACT_NAME = "TSK_PREFETCH"; //NON-NLS
    private static final String APPLICATION_RESOURCE_ARTIFACT_NAME = "TSK_PREFETCH_APPLICATION_RESOURCE"; //NON-NLS

    private static final String ARTIFACT_ATTRIBUTE_NAME = "TSK_ARTIFACT_NAME"; //NON-NLS
    private static final String PREFETCH_FILE_NAME_ART_NAME = "TSK_PREFETCH_FILE_NAME"; //NON-NLS
    private static final String PREFETCH_RUN_COUNT_ART_NAME = "TSK_PF_RUN_COUNT"; //NON-NLS
    private static final String EXECUTION_DTTM_1_ART_NAME = "TSK_PF_EXEC_DTTM_1"; //NON-NLS
    private static final String EXECUTION_DTTM_2_ART_NAME = "TSK_PF_EXEC_DTTM_2"; //NON-NLS
    private static final String EXECUTION_DTTM_3_ART_NAME = "TSK_PF_EXEC_DTTM_3"; //NON-NLS
    private static final String EXECUTION_DTTM_4_ART_NAME = "TSK_PF_EXEC_DTTM_4"; //NON-NLS
    private static final String EXECUTION_DTTM_5_ART_NAME = "TSK_PF_EXEC_DTTM_5"; //NON-NLS
    private static final String EXECUTION_DTTM_6_ART_NAME = "TSK_PF_EXEC_DTTM_6"; //NON-NLS
    private static final String EXECUTION_DTTM_7_ART_NAME = "TSK_PF_EXEC_DTTM_7"; //NON-NLS
    private static final String EXECUTION_DTTM_8_ART_NAME = "TSK_PF_EXEC_DTTM_8"; //NON-NLS

    private static final String MODULE_NAME = "extractPREFETCH"; //NON-NLS

    private static final String PREFETCH_TOOL_FOLDER = "markmckinnon"; //NON-NLS
    private static final String PREFETCH_TOOL_NAME_WINDOWS = "parse_prefetch.exe"; //NON-NLS
    private static final String PREFETCH_OUTPUT_FILE_NAME = "Output.txt"; //NON-NLS
    private static final String PREFETCH_ERROR_FILE_NAME = "Error.txt"; //NON-NLS

    @Messages({
        "ExtractPrefetch_module_name=Windows Prefetch Extractor"
    })
    ExtractPrefetch() {
        this.moduleName = Bundle.ExtractPrefetch_module_name();
    }

    @Override
    void process(Content dataSource, IngestJobContext context, DataSourceIngestModuleProgress progressBar) {

        this.context = context;

        try {
            createPrefetchArtifactType();
        } catch (TskCoreException ex) {
            logger.log(Level.WARNING, String.format("%s, %s or $s may not have been created.", APPLICATION_EXECUTION_ARTIFACT_NAME, PREFETCH_ARTIFACT_NAME, APPLICATION_RESOURCE_ARTIFACT_NAME), ex);
        }

        FileManager fileManager = Case.getCurrentCase().getServices().getFileManager();
        String tempDirPath = RAImageIngestModule.getRATempPath(Case.getCurrentCase(), "prefetch"); //NON-NLS
//       String tempOutPath = Case.getCurrentCase().getModuleDirectory() + File.separator + "prefetch" + File.separator + "Autopsy_PF_DB.db3"; //NON-NLS

        SleuthkitCase skCase = Case.getCurrentCase().getSleuthkitCase();

        List<AbstractFile> pFiles;

        try {
            pFiles = fileManager.findFiles(dataSource, "%.pf"); //NON-NLS            
        } catch (TskCoreException ex) {
            logger.log(Level.WARNING, "Unable to find prefetch files.", ex); //NON-NLS
            return;  // No need to continue
        }

        String prefetchFile = null;
        String tempOutFile = tempDirPath + File.separator + "Autopsy_PF_DB.db3";
        AbstractFile prefetchAbstractFile = null;

        for (AbstractFile pFile : pFiles) {

            if (context.dataSourceIngestIsCancelled()) {
                return;
            }

            prefetchFile = tempDirPath + File.separator + pFile.getName();

            try {
                ContentUtils.writeToFile(pFile, new File(prefetchFile));
            } catch (IOException ex) {
                logger.log(Level.WARNING, String.format("Unable to write %s to temp directory. File name: %s", pFile.getName(), prefetchFile), ex); //NON-NLS
            }

        }

        final String prefetchDumper = getPathForPrefetchDumper();
        if (prefetchDumper == null) {
//            this.addErrorMessage(Bundle.ExtractEdge_process_errMsg_unableFindESEViewer());
            logger.log(Level.SEVERE, "Error finding export_prefetchdb program"); //NON-NLS
            return; //If we cannot find the ESEDatabaseView we cannot proceed
        }

        if (context.dataSourceIngestIsCancelled()) {
            return;
        }

        try {
            extractPrefetchFiles(prefetchDumper, tempDirPath, tempOutFile, tempDirPath);
        } catch (IOException ex) {

        }
        try {
            createPrefetchAttributeType();
            createPrefetchArtifactType();
            createAppExecArtifacts(tempOutFile, dataSource);
            createPrefetchArtifacts(tempOutFile, dataSource);
        } finally {
            return;
        }
//        (new File(tempDirPath)).delete();
    }

    /**
     * Run the export prefetchdb program against the prefetchdb.dat file
     *
     * @param prefetchExePath
     * @param tempDirPath
     * @param tempOutPath
     *
     * @throws FileNotFoundException
     * @throws IOException
     */
    void extractPrefetchFiles(String prefetchExePath, String prefetchFile, String tempOutFile, String tempOutPath) throws FileNotFoundException, IOException {
        final Path outputFilePath = Paths.get(tempOutPath, PREFETCH_OUTPUT_FILE_NAME);
        final Path errFilePath = Paths.get(tempOutPath, PREFETCH_ERROR_FILE_NAME);

        List<String> commandLine = new ArrayList<>();
        commandLine.add(prefetchExePath);
        commandLine.add(prefetchFile);  //NON-NLS
        commandLine.add(tempOutFile);

        ProcessBuilder processBuilder = new ProcessBuilder(commandLine);
        processBuilder.redirectOutput(outputFilePath.toFile());
        processBuilder.redirectError(errFilePath.toFile());

        ExecUtil.execute(processBuilder, new DataSourceIngestModuleProcessTerminator(context));
    }

    private String getPathForPrefetchDumper() {
        Path path = Paths.get(PREFETCH_TOOL_FOLDER, PREFETCH_TOOL_NAME_WINDOWS);
        File prefetchToolFile = InstalledFileLocator.getDefault().locate(path.toString(),
                ExtractPrefetch.class.getPackage().getName(), false);
        if (prefetchToolFile != null) {
            return prefetchToolFile.getAbsolutePath();
        }

        return null;
    }

    private void createAppExecArtifacts(String prefetchDb, Content dataSource) {
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

//        Content prefetchContentFile = prefetchAbstractFile;
        String sqlStatement = "SELECT DISTINCT prefetch_File_name ApplicationName, 'PREFETCH' TableName FROM prefetch_file_info;"; //NON-NLS

        try (SQLiteDBConnect tempdbconnect = new SQLiteDBConnect("org.sqlite.JDBC", "jdbc:sqlite:" + prefetchDb); //NON-NLS
                ResultSet resultSet = tempdbconnect.executeQry(sqlStatement)) {

            while (resultSet.next()) {

                if (context.dataSourceIngestIsCancelled()) {
                    logger.log(Level.INFO, "Cancelled PREFETCH Artifact Creation."); //NON-NLS
                    return;
                }

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

                FileManager fileManager = Case.getCurrentCase().getServices().getFileManager();
                List<AbstractFile> pFiles;
                try {
                    pFiles = fileManager.findFiles(dataSource, applicationName, "Prefetch");
                } catch (TskCoreException ex) {
                    logger.log(Level.WARNING, "Unable to find prefetch files.", ex); //NON-NLS
                    return;  // No need to continue
                }
                for (AbstractFile pFile : pFiles) {
                    try {
                        BlackboardArtifact bbart = pFile.newArtifact(artifactType.getTypeID());
                        bbart.addAttributes(bbattributes);
                        try {
                            /*
                             * Post the artifact which will index the artifact
                             * for keyword search, and fire an event to notify
                             * UI of this new artifact
                             */
                            blackboard.postArtifact(bbart, MODULE_NAME);
                        } catch (Blackboard.BlackboardException ex) {
                            logger.log(Level.SEVERE, "Error Posting Artifact.", ex);//NON-NLS
                        }
                    } catch (TskCoreException ex) {
                        logger.log(Level.SEVERE, "Exception Adding Artifact.", ex);//NON-NLS
                    }
                }
            }
        } catch (SQLException ex) {
            logger.log(Level.SEVERE, "Error while trying to read into a sqlite db.", ex);//NON-NLS
        }
    }

    private void createPrefetchArtifacts(String prefetchDb, Content dataSource) {
        Blackboard blackboard = currentCase.getSleuthkitCase().getBlackboard();
        BlackboardAttribute.Type pfFileNameAttributeType;
        BlackboardAttribute.Type pfRunCountAttributeType;
        BlackboardAttribute.Type pfDttm1AttributeType;        
        BlackboardAttribute.Type pfDttm2AttributeType;        
        BlackboardAttribute.Type pfDttm3AttributeType;        
        BlackboardAttribute.Type pfDttm4AttributeType;        
        BlackboardAttribute.Type pfDttm5AttributeType;        
        BlackboardAttribute.Type pfDttm6AttributeType;        
        BlackboardAttribute.Type pfDttm7AttributeType;        
        BlackboardAttribute.Type pfDttm8AttributeType;        
        BlackboardArtifact.Type artifactType;
 
        try {
            pfFileNameAttributeType = currentCase.getSleuthkitCase().getAttributeType(PREFETCH_FILE_NAME_ART_NAME);
            pfRunCountAttributeType = currentCase.getSleuthkitCase().getAttributeType(PREFETCH_RUN_COUNT_ART_NAME);
            pfDttm1AttributeType = currentCase.getSleuthkitCase().getAttributeType(EXECUTION_DTTM_1_ART_NAME);
            pfDttm2AttributeType = currentCase.getSleuthkitCase().getAttributeType(EXECUTION_DTTM_2_ART_NAME);
            pfDttm3AttributeType = currentCase.getSleuthkitCase().getAttributeType(EXECUTION_DTTM_3_ART_NAME);
            pfDttm4AttributeType = currentCase.getSleuthkitCase().getAttributeType(EXECUTION_DTTM_4_ART_NAME);
            pfDttm5AttributeType = currentCase.getSleuthkitCase().getAttributeType(EXECUTION_DTTM_5_ART_NAME);
            pfDttm6AttributeType = currentCase.getSleuthkitCase().getAttributeType(EXECUTION_DTTM_6_ART_NAME);
            pfDttm7AttributeType = currentCase.getSleuthkitCase().getAttributeType(EXECUTION_DTTM_7_ART_NAME);
            pfDttm8AttributeType = currentCase.getSleuthkitCase().getAttributeType(EXECUTION_DTTM_8_ART_NAME);
            artifactType = currentCase.getSleuthkitCase().getArtifactType(PREFETCH_ARTIFACT_NAME);
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Error Finding Attribute and Artifact in prefetch.", ex);//NON-NLS
            return;
        }

//        Content prefetchContentFile = prefetchAbstractFile;
        String sqlStatement = "SELECT prefetch_File_name, actual_file_Name, Number_time_file_run, Embeded_date_time_Unix_1, " +
                              " Embeded_date_time_Unix_2, Embeded_date_time_Unix_3, Embeded_date_time_Unix_4, " +
                              " Embeded_date_time_Unix_5, Embeded_date_time_Unix_6, Embeded_date_time_Unix_7, " +
                              " Embeded_date_time_Unix_8 FROM prefetch_file_info;"; //NON-NLS

        try (SQLiteDBConnect tempdbconnect = new SQLiteDBConnect("org.sqlite.JDBC", "jdbc:sqlite:" + prefetchDb); //NON-NLS
                ResultSet resultSet = tempdbconnect.executeQry(sqlStatement)) {

            while (resultSet.next()) {

                if (context.dataSourceIngestIsCancelled()) {
                    logger.log(Level.INFO, "Cancelled PREFETCH Artifact Creation."); //NON-NLS
                    return;
                }

                String prefetchFileName = resultSet.getString("prefetch_file_name"); //NON-NLS
                String actualFileName = resultSet.getString("actual_File_Name"); //NON-NLS
                Long numberTimeFileRun = new Long(resultSet.getInt("Number_Time_FIle_Run")); //NON-NLS
                Long execDttmRun1 = new Long(resultSet.getInt("Embeded_date_time_Unix_1")); //NON-NLS
                Long execDttmRun2 = new Long(resultSet.getInt("Embeded_date_time_Unix_2")); //NON-NLS
                Long execDttmRun3 = new Long(resultSet.getInt("Embeded_date_time_Unix_3")); //NON-NLS
                Long execDttmRun4 = new Long(resultSet.getInt("Embeded_date_time_Unix_4")); //NON-NLS
                Long execDttmRun5 = new Long(resultSet.getInt("Embeded_date_time_Unix_5")); //NON-NLS
                Long execDttmRun6 = new Long(resultSet.getInt("Embeded_date_time_Unix_6")); //NON-NLS
                Long execDttmRun7 = new Long(resultSet.getInt("Embeded_date_time_Unix_7")); //NON-NLS
                Long execDttmRun8 = new Long(resultSet.getInt("Embeded_date_time_Unix_8")); //NON-NLS
                

                Collection<BlackboardAttribute> bbattributes = Arrays.asList(
                        //                        new BlackboardAttribute(
                        //                                TSK_DATETIME, getName(),
                        //                                executionTime), //NON-NLS
                        new BlackboardAttribute(
                                pfFileNameAttributeType, getName(),
                                prefetchFileName),//NON-NLS
                        new BlackboardAttribute(
                                TSK_PROG_NAME, getName(),
                                actualFileName),
                        new BlackboardAttribute(
                                pfRunCountAttributeType, getName(),
                                numberTimeFileRun),
                        new BlackboardAttribute(
                                pfDttm1AttributeType, getName(),
                                execDttmRun1),
                        new BlackboardAttribute(
                                pfDttm2AttributeType, getName(),
                                execDttmRun2),
                        new BlackboardAttribute(
                                pfDttm3AttributeType, getName(),
                                execDttmRun3),
                        new BlackboardAttribute(
                                pfDttm4AttributeType, getName(),
                                execDttmRun4),
                        new BlackboardAttribute(
                                pfDttm5AttributeType, getName(),
                                execDttmRun5),
                        new BlackboardAttribute(
                                pfDttm6AttributeType, getName(),
                                execDttmRun6),
                        new BlackboardAttribute(
                                pfDttm7AttributeType, getName(),
                                execDttmRun7),
                        new BlackboardAttribute(
                                pfDttm8AttributeType, getName(),
                                execDttmRun8));

                FileManager fileManager = Case.getCurrentCase().getServices().getFileManager();
                List<AbstractFile> pFiles;
                try {
                    pFiles = fileManager.findFiles(dataSource, prefetchFileName, "Prefetch");
                } catch (TskCoreException ex) {
                    logger.log(Level.WARNING, "Unable to find prefetch files.", ex); //NON-NLS
                    return;  // No need to continue
                }
                for (AbstractFile pFile : pFiles) {
                    try {
                        BlackboardArtifact bbart = pFile.newArtifact(artifactType.getTypeID());
                        bbart.addAttributes(bbattributes);
                        try {
                            /*
                             * Post the artifact which will index the artifact
                             * for keyword search, and fire an event to notify
                             * UI of this new artifact
                             */
                            blackboard.postArtifact(bbart, MODULE_NAME);
                        } catch (Blackboard.BlackboardException ex) {
                            logger.log(Level.SEVERE, "Error Posting Artifact.", ex);//NON-NLS
                        }
                    } catch (TskCoreException ex) {
                        logger.log(Level.SEVERE, "Exception Adding Artifact.", ex);//NON-NLS
                    }
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
    private void createPrefetchArtifactType() throws TskCoreException {

        try {
            tskCase.addBlackboardArtifactType(APPLICATION_EXECUTION_ARTIFACT_NAME, "Application Execution"); //NON-NLS
        } catch (TskDataException ex) {
            logger.log(Level.INFO, String.format("%s may have already been defined for this case", APPLICATION_EXECUTION_ARTIFACT_NAME));
        }
        try {
            tskCase.addBlackboardArtifactType(PREFETCH_ARTIFACT_NAME, "Windows Prefetch"); //NON-NLS
        } catch (TskDataException ex) {
            logger.log(Level.INFO, String.format("%s may have already been defined for this case", PREFETCH_ARTIFACT_NAME));
        }

    }

    /**
     * Create System Resource Usage Attribute type's.
     *
     * @throws TskCoreException
     */
    private void createPrefetchAttributeType() throws TskCoreException {

        try {
            tskCase.addArtifactAttributeType(ARTIFACT_ATTRIBUTE_NAME, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Artifact Name"); //NON-NLS
        } catch (TskDataException ex) {
            logger.log(Level.INFO, String.format("%s may have already been defined for this case", ARTIFACT_ATTRIBUTE_NAME));
        }
        try {
            tskCase.addArtifactAttributeType(PREFETCH_FILE_NAME_ART_NAME, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Prefetch File Name"); //NON-NLS
        } catch (TskDataException ex) {
            logger.log(Level.INFO, String.format("%s may have already been defined for this case", PREFETCH_FILE_NAME_ART_NAME));
        }
        try {
            tskCase.addArtifactAttributeType(PREFETCH_RUN_COUNT_ART_NAME, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "Program Number Runs"); //NON-NLS
        } catch (TskDataException ex) {
            logger.log(Level.INFO, String.format("%s may have already been defined for this case", PREFETCH_RUN_COUNT_ART_NAME));
        }
        try {
            tskCase.addArtifactAttributeType(EXECUTION_DTTM_1_ART_NAME, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "PF Execution DTTM 1"); //NON-NLS
        } catch (TskDataException ex) {
            logger.log(Level.INFO, String.format("%s may have already been defined for this case", EXECUTION_DTTM_1_ART_NAME));
        }
        try {
            tskCase.addArtifactAttributeType(EXECUTION_DTTM_2_ART_NAME, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "PF Execution DTTM 2"); //NON-NLS
        } catch (TskDataException ex) {
            logger.log(Level.INFO, String.format("%s may have already been defined for this case", EXECUTION_DTTM_2_ART_NAME));
        }
        try {
            tskCase.addArtifactAttributeType(EXECUTION_DTTM_3_ART_NAME, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "PF Execution DTTM 3"); //NON-NLS
        } catch (TskDataException ex) {
            logger.log(Level.INFO, String.format("%s may have already been defined for this case", EXECUTION_DTTM_3_ART_NAME));
        }
        try {
            tskCase.addArtifactAttributeType(EXECUTION_DTTM_4_ART_NAME, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "PF Execution DTTM 4"); //NON-NLS
        } catch (TskDataException ex) {
            logger.log(Level.INFO, String.format("%s may have already been defined for this case", EXECUTION_DTTM_4_ART_NAME));
        }
        try {
            tskCase.addArtifactAttributeType(EXECUTION_DTTM_5_ART_NAME, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "PF Execution DTTM 5"); //NON-NLS
        } catch (TskDataException ex) {
            logger.log(Level.INFO, String.format("%s may have already been defined for this case", EXECUTION_DTTM_5_ART_NAME));
        }
        try {
            tskCase.addArtifactAttributeType(EXECUTION_DTTM_6_ART_NAME, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "PF Execution DTTM 6"); //NON-NLS
        } catch (TskDataException ex) {
            logger.log(Level.INFO, String.format("%s may have already been defined for this case", EXECUTION_DTTM_6_ART_NAME));
        }
        try {
            tskCase.addArtifactAttributeType(EXECUTION_DTTM_7_ART_NAME, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "PF Execution DTTM 7"); //NON-NLS
        } catch (TskDataException ex) {
            logger.log(Level.INFO, String.format("%s may have already been defined for this case", EXECUTION_DTTM_7_ART_NAME));
        }
        try {
            tskCase.addArtifactAttributeType(EXECUTION_DTTM_8_ART_NAME, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "PF Execution DTTM 8"); //NON-NLS
        } catch (TskDataException ex) {
            logger.log(Level.INFO, String.format("%s may have already been defined for this case", EXECUTION_DTTM_8_ART_NAME));
        }

    }

}
