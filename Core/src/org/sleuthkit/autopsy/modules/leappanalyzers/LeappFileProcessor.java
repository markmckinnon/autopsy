/*
 * Autopsy Forensic Browser
 *
 * Copyright 2020 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
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
package org.sleuthkit.autopsy.modules.leappanalyzers;

import com.fasterxml.jackson.databind.MappingIterator;
import com.fasterxml.jackson.dataformat.csv.CsvMapper;
import com.fasterxml.jackson.dataformat.csv.CsvParser;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;
import com.google.common.collect.ImmutableMap;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import static java.util.Locale.US;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.openide.util.NbBundle;
import org.sleuthkit.autopsy.casemodule.Case;
import static org.sleuthkit.autopsy.casemodule.Case.getCurrentCase;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.autopsy.centralrepository.datamodel.CorrelationAttributeNormalizer;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.PlatformUtil;
import org.sleuthkit.autopsy.coreutils.NetworkUtils;
import org.sleuthkit.autopsy.ingest.IngestModule.IngestModuleException;
import org.sleuthkit.autopsy.ingest.IngestModule.ProcessResult;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.TskException;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Find and process output from Leapp program and bring into Autopsy
 */
public final class LeappFileProcessor {

    /**
     * Represents metadata for a particular column in a tsv file.
     */
    private static class TsvColumn {

        private final BlackboardAttribute.Type attributeType;
        private final String columnName;
        private final boolean required;

        /**
         * Main constructor.
         *
         * @param attributeType The BlackboardAttribute type or null if not
         * used. used.
         * @param columnName The name of the column in the tsv file.
         * @param required Whether or not this attribute is required to be
         * present.
         */
        TsvColumn(BlackboardAttribute.Type attributeType, String columnName, boolean required) {
            this.attributeType = attributeType;
            this.columnName = columnName;
            this.required = required;
        }

        /**
         * @return The BlackboardAttribute type or null if not used.
         */
        BlackboardAttribute.Type getAttributeType() {
            return attributeType;
        }

        /**
         * @return The name of the column in the tsv file.
         */
        String getColumnName() {
            return columnName;
        }

        /**
         * @return Whether or not this attribute is required to be present.
         */
        boolean isRequired() {
            return required;
        }
    }

    private static final Logger logger = Logger.getLogger(LeappFileProcessor.class.getName());
    private final String xmlFile; //NON-NLS
    private final String moduleName;

    private final Map<String, String> tsvFiles;
    private final Map<String, BlackboardArtifact.Type> tsvFileArtifacts;
    private final Map<String, String> tsvFileArtifactComments;
    private final Map<String, List<TsvColumn>> tsvFileAttributes;

    private static final Map<String, String> CUSTOM_ARTIFACT_MAP = ImmutableMap.<String, String>builder()
            .put("TSK_IP_DHCP", "DHCP Information")
            .build();

    Blackboard blkBoard;

    public LeappFileProcessor(String xmlFile, String moduleName) throws IOException, IngestModuleException, NoCurrentCaseException {
        this.tsvFiles = new HashMap<>();
        this.tsvFileArtifacts = new HashMap<>();
        this.tsvFileArtifactComments = new HashMap<>();
        this.tsvFileAttributes = new HashMap<>();
        this.xmlFile = xmlFile;
        this.moduleName = moduleName;

        blkBoard = Case.getCurrentCaseThrows().getSleuthkitCase().getBlackboard();

        createCustomArtifacts(blkBoard);
        configExtractor();
        loadConfigFile();

    }

    @NbBundle.Messages({
        "LeappFileProcessor.error.running.Leapp=Error running Leapp, see log file.",
        "LeappFileProcessor.error.creating.output.dir=Error creating Leapp module output directory.",
        "LeappFileProcessor.starting.Leapp=Starting Leapp",
        "LeappFileProcessor.running.Leapp=Running Leapp",
        "LeappFileProcessor.has.run=Leapp",
        "LeappFileProcessor.Leapp.cancelled=Leapp run was canceled",
        "LeappFileProcessor.completed=Leapp Processing Completed",
        "LeappFileProcessor.error.reading.Leapp.directory=Error reading Leapp Output Directory"})
    public ProcessResult processFiles(Content dataSource, Path moduleOutputPath, AbstractFile LeappFile) {
        try {
            List<String> LeappTsvOutputFiles = findTsvFiles(moduleOutputPath);
            processLeappFiles(LeappTsvOutputFiles, LeappFile);
        } catch (IOException | IngestModuleException ex) {
            logger.log(Level.SEVERE, String.format("Error trying to process Leapp output files in directory %s. ", moduleOutputPath.toString()), ex); //NON-NLS
            return ProcessResult.ERROR;
        }

        return ProcessResult.OK;
    }

    public ProcessResult processFileSystem(Content dataSource, Path moduleOutputPath) {

        try {
            List<String> LeappTsvOutputFiles = findTsvFiles(moduleOutputPath);
            processLeappFiles(LeappTsvOutputFiles, dataSource);
        } catch (IngestModuleException ex) {
            logger.log(Level.SEVERE, String.format("Error trying to process Leapp output files in directory %s. ", moduleOutputPath.toString()), ex); //NON-NLS
            return ProcessResult.ERROR;
        }

        return ProcessResult.OK;
    }

    /**
     * Find the tsv files in the Leapp output directory and match them to files
     * we know we want to process and return the list to process those files.
     */
    private List<String> findTsvFiles(Path LeappOutputDir) throws IngestModuleException {
        List<String> allTsvFiles = new ArrayList<>();
        List<String> foundTsvFiles = new ArrayList<>();

        try (Stream<Path> walk = Files.walk(LeappOutputDir)) {

            allTsvFiles = walk.map(x -> x.toString())
                    .filter(f -> f.toLowerCase().endsWith(".tsv")).collect(Collectors.toList());

            for (String tsvFile : allTsvFiles) {
                if (tsvFiles.containsKey(FilenameUtils.getName(tsvFile.toLowerCase()))) {
                    foundTsvFiles.add(tsvFile);
                }
            }

        } catch (IOException | UncheckedIOException e) {
            throw new IngestModuleException(Bundle.LeappFileProcessor_error_reading_Leapp_directory() + LeappOutputDir.toString(), e);
        }

        return foundTsvFiles;

    }

    /**
     * Process the Leapp files that were found that match the xml mapping file
     *
     * @param LeappFilesToProcess List of files to process
     * @param LeappImageFile Abstract file to create artifact for
     *
     * @throws FileNotFoundException
     * @throws IOException
     */
    private void processLeappFiles(List<String> LeappFilesToProcess, AbstractFile LeappImageFile) throws FileNotFoundException, IOException, IngestModuleException {
        List<BlackboardArtifact> bbartifacts = new ArrayList<>();

        for (String LeappFileName : LeappFilesToProcess) {
            String fileName = FilenameUtils.getName(LeappFileName);
            File LeappFile = new File(LeappFileName);
            if (tsvFileAttributes.containsKey(fileName)) {
                BlackboardArtifact.Type artifactType = null;
                try {
                    List<TsvColumn> attrList = tsvFileAttributes.get(fileName);
                    artifactType = tsvFileArtifacts.get(fileName);
                    processFile(LeappFile, attrList, fileName, artifactType, bbartifacts, LeappImageFile);
                } catch (TskCoreException ex) {
                    throw new IngestModuleException(String.format("Error getting Blackboard Artifact Type for %s", artifactType == null ? "<null>" : artifactType.toString()), ex);
                }
            }
        }

        if (!bbartifacts.isEmpty()) {
            postArtifacts(bbartifacts);
        }

    }

    /**
     * Process the Leapp files that were found that match the xml mapping file
     *
     * @param LeappFilesToProcess List of files to process
     * @param dataSource The data source.
     *
     * @throws FileNotFoundException
     * @throws IOException
     */
    private void processLeappFiles(List<String> LeappFilesToProcess, Content dataSource) throws IngestModuleException {
        List<BlackboardArtifact> bbartifacts = new ArrayList<>();

        for (String LeappFileName : LeappFilesToProcess) {
            String fileName = FilenameUtils.getName(LeappFileName);
            File LeappFile = new File(LeappFileName);
            if (tsvFileAttributes.containsKey(fileName)) {
                List<TsvColumn> attrList = tsvFileAttributes.get(fileName);
                BlackboardArtifact.Type artifactType = tsvFileArtifacts.get(fileName);

                try {
                    processFile(LeappFile, attrList, fileName, artifactType, bbartifacts, dataSource);
                } catch (TskCoreException | IOException ex) {
                    logger.log(Level.SEVERE, String.format("Error processing file at %s", LeappFile.toString()), ex);
                }
            }

        }

        if (!bbartifacts.isEmpty()) {
            postArtifacts(bbartifacts);
        }

    }

    private void processFile(File LeappFile, List<TsvColumn> attrList, String fileName, BlackboardArtifact.Type artifactType,
            List<BlackboardArtifact> bbartifacts, Content dataSource) throws FileNotFoundException, IOException, IngestModuleException,
            TskCoreException {

        if (LeappFile == null || !LeappFile.exists() || fileName == null) {
            logger.log(Level.WARNING, String.format("Leap file: %s is null or does not exist", LeappFile == null ? LeappFile.toString() : "<null>"));
            return;
        } else if (attrList == null || artifactType == null || dataSource == null) {
            logger.log(Level.WARNING, String.format("attribute list, artifact type or dataSource not provided for %s", LeappFile == null ? LeappFile.toString() : "<null>"));
            return;
        }

        // based on https://stackoverflow.com/questions/56921465/jackson-csv-schema-for-array
        try (MappingIterator<List<String>> iterator = new CsvMapper()
                .enable(CsvParser.Feature.WRAP_AS_ARRAY)
                .readerFor(List.class)
                .with(CsvSchema.emptySchema().withColumnSeparator('\t'))
                .readValues(LeappFile)) {

            if (iterator.hasNext()) {
                List<String> headerItems = iterator.next();
                Map<String, Integer> columnIndexes = IntStream.range(0, headerItems.size())
                        .mapToObj(idx -> idx)
                        .collect(Collectors.toMap(
                                idx -> headerItems.get(idx) == null ? null : headerItems.get(idx).trim().toLowerCase(),
                                idx -> idx,
                                (val1, val2) -> val1));

                int lineNum = 2;
                while (iterator.hasNext()) {
                    List<String> columnItems = iterator.next();
                    Collection<BlackboardAttribute> bbattributes = processReadLine(columnItems, columnIndexes, attrList, fileName, lineNum);

                    if (!bbattributes.isEmpty()) {
                        BlackboardArtifact bbartifact = createArtifactWithAttributes(artifactType.getTypeID(), dataSource, bbattributes);
                        if (bbartifact != null) {
                            bbartifacts.add(bbartifact);
                        }
                    }

                    lineNum++;
                }
            }
        }
    }

    /**
     * Process the line read and create the necessary attributes for it.
     *
     * @param lineValues List of column values.
     * @param columnIndexes Mapping of column headers (trimmed; to lower case)
     * to column index. All header columns and only all header columns should be
     * present.
     * @param attrList The list of attributes as specified for the schema of
     * this file.
     * @param fileName The name of the file being processed.
     * @param lineNum The line number in the file.
     * @return The collection of blackboard attributes for the artifact created
     * from this line.
     * @throws IngestModuleException
     */
    private Collection<BlackboardAttribute> processReadLine(List<String> lineValues, Map<String, Integer> columnIndexes,
            List<TsvColumn> attrList, String fileName, int lineNum) throws IngestModuleException {

        if (MapUtils.isEmpty(columnIndexes) || CollectionUtils.isEmpty(lineValues)
                || (lineValues.size() == 1 && StringUtils.isEmpty(lineValues.get(0)))) {
            return Collections.emptyList();
        } else if (lineValues.size() != columnIndexes.size()) {
            logger.log(Level.WARNING, String.format(
                    "Row at line number %d in file %s has %d columns when %d were expected based on the header row.",
                    lineNum, fileName, lineValues.size(), columnIndexes.size()));
            return Collections.emptyList();
        }

        List<BlackboardAttribute> attrsToRet = new ArrayList<>();
        for (TsvColumn colAttr : attrList) {
            if (colAttr.getAttributeType() == null) {
                // this handles columns that are currently ignored.
                continue;
            }

            Integer columnIdx = columnIndexes.get(colAttr.getColumnName());
            if (columnIdx == null) {
                logger.log(Level.WARNING, String.format("No column mapping found for %s in file %s.  Omitting column.", colAttr.getColumnName(), fileName));
                continue;
            }
            
            if (colAttr.getAttributeType().getTypeName().equals("TSK_DOMAIN")) {
                    logger.log(Level.INFO, "Domain Attribute");
            }
            //formatValueBasedOnAttr(value)

            String value = (columnIdx >= lineValues.size() || columnIdx < 0) ? null : lineValues.get(columnIdx);
            if (value == null) {
                logger.log(Level.WARNING, String.format("No value found for column %s at line %d in file %s.  Omitting row.", colAttr.getColumnName(), lineNum, fileName));
                return Collections.emptyList();
            }

            String formattedValue = formatValueBasedOnAttrType(colAttr, value);
            
            BlackboardAttribute attr = (value == null) ? null : getAttribute(colAttr.getAttributeType(), formattedValue, fileName);
            if (attr == null) {
                logger.log(Level.WARNING, String.format("Blackboard attribute could not be parsed column %s at line %d in file %s.  Omitting row.", colAttr.getColumnName(), lineNum, fileName));
                return Collections.emptyList();
            }
            attrsToRet.add(attr);
        }

        if (tsvFileArtifactComments.containsKey(fileName)) {
            attrsToRet.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_COMMENT, moduleName, tsvFileArtifactComments.get(fileName)));
        }

        return attrsToRet;
    }
    
    /**
     * Check type of attribute and possibly format string based on it.
     * 
     * @param colAttr Column Attribute information
     * @param value string to be formatted
     * @return formatted string based on attribute type if no attribute type found then return original string 
     */
    private String formatValueBasedOnAttrType(TsvColumn colAttr, String value) {
        if (colAttr.getAttributeType().getTypeName().equals("TSK_DOMAIN")) {
            return NetworkUtils.extractDomain(value);
        }
        
        return value;
    }

    /**
     * The format of time stamps in tsv.
     */
    private static final DateFormat TIMESTAMP_FORMAT = new SimpleDateFormat("yyyy-MM-d HH:mm:ss", US);

    /**
     * Gets an appropriate attribute based on the attribute type and string
     * value.
     *
     * @param attrType The attribute type.
     * @param value The string value to be converted to the appropriate data
     * type for the attribute type.
     * @param fileName The file name that the value comes from.
     * @return The generated blackboard attribute.
     */
    private BlackboardAttribute getAttribute(BlackboardAttribute.Type attrType, String value, String fileName) {
        if (attrType == null || value == null) {
            logger.log(Level.WARNING, String.format("Unable to parse attribute type %s for value '%s' in fileName %s",
                    attrType == null ? "<null>" : attrType.toString(),
                    value == null ? "<null>" : value,
                    fileName == null ? "<null>" : fileName));
            return null;
        }

        switch (attrType.getValueType()) {
            case JSON:
            case STRING:
                return parseAttrValue(value, attrType, fileName, false, false,
                        (v) -> new BlackboardAttribute(attrType, moduleName, v));
            case INTEGER:
                return parseAttrValue(value.trim(), attrType, fileName, true, false,
                        (v) -> new BlackboardAttribute(attrType, moduleName, Double.valueOf(v).intValue()));
            case LONG:
                return parseAttrValue(value.trim(), attrType, fileName, true, false,
                        (v) -> new BlackboardAttribute(attrType, moduleName, Double.valueOf(v).longValue()));
            case DOUBLE:
                return parseAttrValue(value.trim(), attrType, fileName, true, false,
                        (v) -> new BlackboardAttribute(attrType, moduleName, (double) Double.valueOf(v)));
            case BYTE:
                return parseAttrValue(value.trim(), attrType, fileName, true, false,
                        (v) -> new BlackboardAttribute(attrType, moduleName, new byte[]{Byte.valueOf(v)}));
            case DATETIME:
                return parseAttrValue(value.trim(), attrType, fileName, true, true,
                        (v) -> new BlackboardAttribute(attrType, moduleName, TIMESTAMP_FORMAT.parse(v).getTime() / 1000));
            default:
                // Log this and continue on with processing
                logger.log(Level.WARNING, String.format("Attribute Type %s for file %s not defined.", attrType, fileName)); //NON-NLS                   
                return null;
        }
    }

    /**
     * Handles converting a string to a blackboard attribute.
     */
    private interface ParseExceptionFunction {

        /**
         * Handles converting a string value to a blackboard attribute.
         *
         * @param orig The original string value.
         * @return The generated blackboard attribute.
         * @throws ParseException
         * @throws NumberFormatException
         */
        BlackboardAttribute apply(String orig) throws ParseException, NumberFormatException;
    }

    /**
     * Runs parsing function on string value to convert to right data type and
     * generates a blackboard attribute for that converted data type.
     *
     * @param value The string value.
     * @param attrType The blackboard attribute type.
     * @param fileName The name of the file from which the value comes.
     * @param blankIsNull If string is blank return null attribute.
     * @param zeroIsNull If string is some version of 0, return null attribute.
     * @param valueConverter The means of converting the string value to an
     * appropriate blackboard attribute.
     * @return The generated blackboard attribute or null if not determined.
     */
    private BlackboardAttribute parseAttrValue(String value, BlackboardAttribute.Type attrType, String fileName, boolean blankIsNull, boolean zeroIsNull, ParseExceptionFunction valueConverter) {
        // remove non-printable characters from tsv input
        // https://stackoverflow.com/a/6199346
        value = value.replaceAll("\\p{C}", "");

        if (blankIsNull && StringUtils.isBlank(value)) {
            return null;
        }

        if (zeroIsNull && value.matches("^\\s*[0\\.]*\\s*$")) {
            return null;
        }

        try {
            return valueConverter.apply(value);
        } catch (NumberFormatException | ParseException ex) {
            logger.log(Level.WARNING, String.format("Unable to format '%s' as value type %s while converting to attributes from %s.", value, attrType.getValueType().getLabel(), fileName), ex);
            return null;
        }
    }

    @NbBundle.Messages({
        "LeappFileProcessor.cannot.load.artifact.xml=Cannor load xml artifact file.",
        "LeappFileProcessor.cannotBuildXmlParser=Cannot buld an XML parser.",
        "LeappFileProcessor_cannotParseXml=Cannot Parse XML file.",
        "LeappFileProcessor.postartifacts_error=Error posting Blackboard Artifact",
        "LeappFileProcessor.error.creating.new.artifacts=Error creating new artifacts."
    })

    /**
     * Read the XML config file and load the mappings into maps
     */
    private void loadConfigFile() throws IngestModuleException {
        Document xmlinput;
        try {
            String path = PlatformUtil.getUserConfigDirectory() + File.separator + xmlFile;
            File f = new File(path);
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            xmlinput = db.parse(f);

        } catch (IOException e) {
            throw new IngestModuleException(Bundle.LeappFileProcessor_cannot_load_artifact_xml() + e.getLocalizedMessage(), e); //NON-NLS
        } catch (ParserConfigurationException pce) {
            throw new IngestModuleException(Bundle.LeappFileProcessor_cannotBuildXmlParser() + pce.getLocalizedMessage(), pce); //NON-NLS
        } catch (SAXException sxe) {
            throw new IngestModuleException(Bundle.LeappFileProcessor_cannotParseXml() + sxe.getLocalizedMessage(), sxe); //NON-NLS
        }

        getFileNode(xmlinput);
        getArtifactNode(xmlinput);
        getAttributeNodes(xmlinput);

    }

    private void getFileNode(Document xmlinput) {

        NodeList nlist = xmlinput.getElementsByTagName("FileName"); //NON-NLS

        for (int i = 0; i < nlist.getLength(); i++) {
            NamedNodeMap nnm = nlist.item(i).getAttributes();
            tsvFiles.put(nnm.getNamedItem("filename").getNodeValue().toLowerCase(), nnm.getNamedItem("description").getNodeValue());

        }

    }

    private void getArtifactNode(Document xmlinput) {

        NodeList artifactNlist = xmlinput.getElementsByTagName("ArtifactName"); //NON-NLS
        for (int k = 0; k < artifactNlist.getLength(); k++) {
            NamedNodeMap nnm = artifactNlist.item(k).getAttributes();
            String artifactName = nnm.getNamedItem("artifactname").getNodeValue();
            String comment = nnm.getNamedItem("comment").getNodeValue();
            String parentName = artifactNlist.item(k).getParentNode().getAttributes().getNamedItem("filename").getNodeValue();

            BlackboardArtifact.Type foundArtifactType = null;
            try {
                foundArtifactType = Case.getCurrentCase().getSleuthkitCase().getArtifactType(artifactName);
            } catch (TskCoreException ex) {
                logger.log(Level.SEVERE, String.format("There was an issue that arose while trying to fetch artifact type for %s.", artifactName), ex);
            }

            if (foundArtifactType == null) {
                logger.log(Level.SEVERE, String.format("No known artifact mapping found for [artifact: %s, %s]",
                        artifactName, getXmlFileIdentifier(parentName)));
            } else {
                tsvFileArtifacts.put(parentName, foundArtifactType);
            }

            if (!comment.toLowerCase().matches("null")) {
                tsvFileArtifactComments.put(parentName, comment);
            }
        }

    }

    private String getXmlFileIdentifier(String fileName) {
        return String.format("file: %s, filename: %s",
                this.xmlFile == null ? "<null>" : this.xmlFile,
                fileName == null ? "<null>" : fileName);
    }

    private String getXmlAttrIdentifier(String fileName, String attributeName) {
        return String.format("attribute: %s %s",
                attributeName == null ? "<null>" : attributeName,
                getXmlFileIdentifier(fileName));
    }

    private void getAttributeNodes(Document xmlinput) {

        NodeList attributeNlist = xmlinput.getElementsByTagName("AttributeName"); //NON-NLS
        for (int k = 0; k < attributeNlist.getLength(); k++) {
            NamedNodeMap nnm = attributeNlist.item(k).getAttributes();
            String attributeName = nnm.getNamedItem("attributename").getNodeValue();

            if (!attributeName.toLowerCase().matches("null")) {
                String columnName = nnm.getNamedItem("columnName").getNodeValue();
                String required = nnm.getNamedItem("required").getNodeValue();
                String parentName = attributeNlist.item(k).getParentNode().getParentNode().getAttributes().getNamedItem("filename").getNodeValue();

                BlackboardAttribute.Type foundAttrType = null;
                try {
                    foundAttrType = Case.getCurrentCase().getSleuthkitCase().getAttributeType(attributeName.toUpperCase());
                } catch (TskCoreException ex) {
                    logger.log(Level.SEVERE, String.format("There was an issue that arose while trying to fetch attribute type for %s.", attributeName), ex);
                }

                if (foundAttrType == null) {
                    logger.log(Level.SEVERE, String.format("No known attribute mapping found for [%s]", getXmlAttrIdentifier(parentName, attributeName)));
                }

                if (required != null && required.compareToIgnoreCase("yes") != 0 && required.compareToIgnoreCase("no") != 0) {
                    logger.log(Level.SEVERE, String.format("Required value %s did not match 'yes' or 'no' for [%s]",
                            required, getXmlAttrIdentifier(parentName, attributeName)));
                }

                if (columnName == null) {
                    logger.log(Level.SEVERE, String.format("No column name provided for [%s]", getXmlAttrIdentifier(parentName, attributeName)));
                } else if (columnName.trim().length() != columnName.length()) {
                    logger.log(Level.SEVERE, String.format("Column name '%s' starts or ends with whitespace for [%s]", columnName, getXmlAttrIdentifier(parentName, attributeName)));
                } else if (columnName.matches("[^ \\S]")) {
                    logger.log(Level.SEVERE, String.format("Column name '%s' contains invalid characters [%s]", columnName, getXmlAttrIdentifier(parentName, attributeName)));
                }

                TsvColumn thisCol = new TsvColumn(
                        foundAttrType,
                        columnName.trim().toLowerCase(),
                        "yes".compareToIgnoreCase(required) == 0);

                if (tsvFileAttributes.containsKey(parentName)) {
                    List<TsvColumn> attrList = tsvFileAttributes.get(parentName);
                    attrList.add(thisCol);
                    tsvFileAttributes.replace(parentName, attrList);
                } else {
                    List<TsvColumn> attrList = new ArrayList<>();
                    attrList.add(thisCol);
                    tsvFileAttributes.put(parentName, attrList);
                }
            }

        }
    }

    /**
     * Generic method for creating a blackboard artifact with attributes
     *
     * @param type is a blackboard.artifact_type enum to determine which type
     * the artifact should be
     * @param dataSource is the Content object that needs to have the artifact
     * added for it
     * @param bbattributes is the collection of blackboard attributes that need
     * to be added to the artifact after the artifact has been created
     *
     * @return The newly-created artifact, or null on error
     */
    private BlackboardArtifact createArtifactWithAttributes(int type, Content dataSource, Collection<BlackboardAttribute> bbattributes) {
        try {
            BlackboardArtifact bbart = dataSource.newArtifact(type);
            bbart.addAttributes(bbattributes);
            return bbart;
        } catch (TskException ex) {
            logger.log(Level.WARNING, Bundle.LeappFileProcessor_error_creating_new_artifacts(), ex); //NON-NLS
        }
        return null;
    }

    /**
     * Method to post a list of BlackboardArtifacts to the blackboard.
     *
     * @param artifacts A list of artifacts. IF list is empty or null, the
     * function will return.
     */
    void postArtifacts(Collection<BlackboardArtifact> artifacts) {
        if (artifacts == null || artifacts.isEmpty()) {
            return;
        }

        try {
            Case.getCurrentCase().getSleuthkitCase().getBlackboard().postArtifacts(artifacts, moduleName);
        } catch (Blackboard.BlackboardException ex) {
            logger.log(Level.SEVERE, Bundle.LeappFileProcessor_postartifacts_error(), ex); //NON-NLS
        }
    }

    /**
     * Extract the Leapp config xml file to the user directory to process
     *
     * @throws org.sleuthkit.autopsy.ingest.IngestModule.IngestModuleException
     */
    private void configExtractor() throws IOException {
        PlatformUtil.extractResourceToUserConfigDir(LeappFileProcessor.class,
                xmlFile, true);
    }

    private static final Set<String> ALLOWED_EXTENSIONS = new HashSet<>(Arrays.asList("zip", "tar", "tgz"));

    /**
     * Find the files that will be processed by the iLeapp program
     *
     * @param dataSource
     *
     * @return List of abstract files to process.
     */
    static List<AbstractFile> findLeappFilesToProcess(Content dataSource) {

        List<AbstractFile> leappFiles = new ArrayList<>();

        FileManager fileManager = getCurrentCase().getServices().getFileManager();

        // findFiles use the SQL wildcard % in the file name
        try {
            leappFiles = fileManager.findFiles(dataSource, "%", "/"); //NON-NLS
        } catch (TskCoreException ex) {
            logger.log(Level.WARNING, "No files found to process"); //NON-NLS
            return leappFiles;
        }

        List<AbstractFile> leappFilesToProcess = new ArrayList<>();
        for (AbstractFile leappFile : leappFiles) {
            if (((leappFile.getLocalAbsPath() != null)
                    && !leappFile.isVirtual())
                    && leappFile.getNameExtension() != null
                    && ALLOWED_EXTENSIONS.contains(leappFile.getNameExtension().toLowerCase())) {
                leappFilesToProcess.add(leappFile);
            }
        }

        return leappFilesToProcess;
    }

    /**
     * Create custom artifacts that are defined in the xLeapp xml file(s).
     *
     */
    private void createCustomArtifacts(Blackboard blkBoard) {

        for (Map.Entry<String, String> customArtifact : CUSTOM_ARTIFACT_MAP.entrySet()) {
            String artifactName = customArtifact.getKey();
            String artifactDescription = customArtifact.getValue();

            try {
                BlackboardArtifact.Type customArtifactType = blkBoard.getOrAddArtifactType(artifactName, artifactDescription);
            } catch (Blackboard.BlackboardException ex) {
                logger.log(Level.WARNING, String.format("Failed to create custom artifact type %s.", artifactName), ex);
            }

        }
    }
}
