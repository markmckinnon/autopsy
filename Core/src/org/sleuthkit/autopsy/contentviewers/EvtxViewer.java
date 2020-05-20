/*
 * Autopsy Forensic Browser
 *
 * Copyright 2018-2019 Basis Technology Corp.
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
package org.sleuthkit.autopsy.contentviewers;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Cursor;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.logging.Level;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.apache.commons.io.FilenameUtils;
import org.openide.util.NbBundle;
import org.openide.windows.WindowManager;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.coreutils.SQLiteTableReaderException;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.MessageNotifyUtil;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.autopsy.coreutils.SQLiteTableReader;

/**
 * A file content viewer for Windows Evtx files, reads a SQLite db of Eventlogs created by RA Evtx Parser.
 */
@SuppressWarnings("PMD.SingularField") // UI widgets cause lots of false positives
class EvtxViewer extends javax.swing.JPanel implements FileTypeViewer {

    private static final long serialVersionUID = 1L;
    public static final String[] SUPPORTED_MIMETYPES = new String[]{"application/x.windows-evtx-logs"};
    private static final int ROWS_PER_PAGE = 100;
    private static final Logger logger = Logger.getLogger(FileViewer.class.getName());
    private final SQLiteTableView selectedTableView = new SQLiteTableView();
    private AbstractFile sqliteDbFile;
    private static final String LOG_FILE_EXTENSION = "evtx"; //base extension for log files
    
    private String actualFileName;

    private SQLiteTableReader viewReader;

    private Map<String, Object> row = new LinkedHashMap<>();
    private List<Map<String, Object>> pageOfTableRows = new ArrayList<>();
    private List<String> currentTableHeader = new ArrayList<>();
    private String prevTableName;

    private int numRows;    // num of rows in the selected table
    private int currPage = 0; // curr page of rows being displayed

    /**
     * Constructs a file content viewer for SQLite database files.
     */
    EvtxViewer() {
        initComponents();
        jTableDataPanel.add(selectedTableView, BorderLayout.CENTER);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jHdrPanel = new javax.swing.JPanel();
        tablesDropdownList = new javax.swing.JComboBox<>();
        numEntriesField = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        currPageLabel = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        numPagesLabel = new javax.swing.JLabel();
        prevPageButton = new javax.swing.JButton();
        nextPageButton = new javax.swing.JButton();
        exportCsvButton = new javax.swing.JButton();
        jTableDataPanel = new javax.swing.JPanel();

        jHdrPanel.setPreferredSize(new java.awt.Dimension(536, 40));

        tablesDropdownList.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Item 1", "Item 2", "Item 3", "Item 4" }));
        tablesDropdownList.setEnabled(false);
        tablesDropdownList.setFocusable(false);
        tablesDropdownList.setOpaque(false);
        tablesDropdownList.addComponentListener(new java.awt.event.ComponentAdapter() {
            public void componentHidden(java.awt.event.ComponentEvent evt) {
                tablesDropdownListComponentHidden(evt);
            }
        });
        tablesDropdownList.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                tablesDropdownListActionPerformed(evt);
            }
        });

        numEntriesField.setEditable(false);
        numEntriesField.setText(org.openide.util.NbBundle.getMessage(EvtxViewer.class, "EvtxViewer.numEntriesField.text")); // NOI18N
        numEntriesField.setBorder(null);

        org.openide.awt.Mnemonics.setLocalizedText(jLabel2, org.openide.util.NbBundle.getMessage(EvtxViewer.class, "EvtxViewer.jLabel2.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(currPageLabel, org.openide.util.NbBundle.getMessage(EvtxViewer.class, "EvtxViewer.currPageLabel.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(jLabel3, org.openide.util.NbBundle.getMessage(EvtxViewer.class, "EvtxViewer.jLabel3.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(numPagesLabel, org.openide.util.NbBundle.getMessage(EvtxViewer.class, "EvtxViewer.numPagesLabel.text")); // NOI18N

        prevPageButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/org/sleuthkit/autopsy/corecomponents/btn_step_back.png"))); // NOI18N
        org.openide.awt.Mnemonics.setLocalizedText(prevPageButton, org.openide.util.NbBundle.getMessage(EvtxViewer.class, "EvtxViewer.prevPageButton.text")); // NOI18N
        prevPageButton.setBorderPainted(false);
        prevPageButton.setContentAreaFilled(false);
        prevPageButton.setDisabledSelectedIcon(new javax.swing.ImageIcon(getClass().getResource("/org/sleuthkit/autopsy/corecomponents/btn_step_back_disabled.png"))); // NOI18N
        prevPageButton.setMargin(new java.awt.Insets(2, 0, 2, 0));
        prevPageButton.setPreferredSize(new java.awt.Dimension(23, 23));
        prevPageButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                prevPageButtonActionPerformed(evt);
            }
        });

        nextPageButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/org/sleuthkit/autopsy/corecomponents/btn_step_forward.png"))); // NOI18N
        org.openide.awt.Mnemonics.setLocalizedText(nextPageButton, org.openide.util.NbBundle.getMessage(EvtxViewer.class, "EvtxViewer.nextPageButton.text")); // NOI18N
        nextPageButton.setBorderPainted(false);
        nextPageButton.setContentAreaFilled(false);
        nextPageButton.setDisabledSelectedIcon(new javax.swing.ImageIcon(getClass().getResource("/org/sleuthkit/autopsy/corecomponents/btn_step_forward_disabled.png"))); // NOI18N
        nextPageButton.setMargin(new java.awt.Insets(2, 0, 2, 0));
        nextPageButton.setPreferredSize(new java.awt.Dimension(23, 23));
        nextPageButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                nextPageButtonActionPerformed(evt);
            }
        });

        org.openide.awt.Mnemonics.setLocalizedText(exportCsvButton, org.openide.util.NbBundle.getMessage(EvtxViewer.class, "EvtxViewer.exportCsvButton.text")); // NOI18N
        exportCsvButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                exportCsvButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jHdrPanelLayout = new javax.swing.GroupLayout(jHdrPanel);
        jHdrPanel.setLayout(jHdrPanelLayout);
        jHdrPanelLayout.setHorizontalGroup(
            jHdrPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jHdrPanelLayout.createSequentialGroup()
                .addGap(102, 102, 102)
                .addComponent(tablesDropdownList, javax.swing.GroupLayout.PREFERRED_SIZE, 130, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(numEntriesField, javax.swing.GroupLayout.PREFERRED_SIZE, 71, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(15, 15, 15)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(currPageLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(numPagesLabel)
                .addGap(18, 18, 18)
                .addComponent(prevPageButton, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, 0)
                .addComponent(nextPageButton, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(29, 29, 29)
                .addComponent(exportCsvButton)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jHdrPanelLayout.setVerticalGroup(
            jHdrPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jHdrPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jHdrPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(exportCsvButton)
                    .addComponent(nextPageButton, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(prevPageButton, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(jHdrPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(tablesDropdownList, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(numEntriesField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(jLabel2)
                        .addComponent(currPageLabel)
                        .addComponent(jLabel3)
                        .addComponent(numPagesLabel)))
                .addContainerGap())
        );

        jTableDataPanel.addComponentListener(new java.awt.event.ComponentAdapter() {
            public void componentHidden(java.awt.event.ComponentEvent evt) {
                jTableDataPanelComponentHidden(evt);
            }
        });
        jTableDataPanel.setLayout(new java.awt.BorderLayout());

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jHdrPanel, javax.swing.GroupLayout.PREFERRED_SIZE, 569, Short.MAX_VALUE)
            .addComponent(jTableDataPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(jHdrPanel, javax.swing.GroupLayout.PREFERRED_SIZE, 53, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, 0)
                .addComponent(jTableDataPanel, javax.swing.GroupLayout.DEFAULT_SIZE, 317, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void nextPageButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_nextPageButtonActionPerformed
        WindowManager.getDefault().getMainWindow().setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
        currPage++;
        if (currPage * ROWS_PER_PAGE > numRows) {
            nextPageButton.setEnabled(false);
        }
        currPageLabel.setText(Integer.toString(currPage));
        prevPageButton.setEnabled(true);

        // read and display a page of rows
        String tableName = (String) this.tablesDropdownList.getSelectedItem();
        readTable(tableName, (currPage - 1) * ROWS_PER_PAGE + 1, ROWS_PER_PAGE);
        WindowManager.getDefault().getMainWindow().setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
    }//GEN-LAST:event_nextPageButtonActionPerformed

    private void prevPageButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_prevPageButtonActionPerformed

        WindowManager.getDefault().getMainWindow().setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
        currPage--;
        if (currPage == 1) {
            prevPageButton.setEnabled(false);
        }
        currPageLabel.setText(Integer.toString(currPage));
        nextPageButton.setEnabled(true);

        // read and display a page of rows
        String tableName = (String) this.tablesDropdownList.getSelectedItem();
        readTable(tableName, (currPage - 1) * ROWS_PER_PAGE + 1, ROWS_PER_PAGE);
        WindowManager.getDefault().getMainWindow().setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
    }//GEN-LAST:event_prevPageButtonActionPerformed

    /**
     * The action when the Export Csv button is pressed. The file chooser window
     * will pop up to choose where the user wants to save the csv file. The
     * default location is case export directory.
     *
     * @param evt the action event
     */
    @NbBundle.Messages({"ExtViewer.csvExport.fileName.empty=Please input a file name for exporting.",
        "ExtViewer.csvExport.title=Export to csv file",
        "ExtViewer.csvExport.confirm.msg=Do you want to overwrite the existing file?"})
    private void exportCsvButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_exportCsvButtonActionPerformed
        Case openCase = Case.getCurrentCase();
        File caseDirectory = new File(openCase.getExportDirectory());
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDragEnabled(false);
        fileChooser.setCurrentDirectory(caseDirectory);
        //Set a filter to let the filechooser only work for csv files
        FileNameExtensionFilter csvFilter = new FileNameExtensionFilter("*.csv", "csv");
        fileChooser.addChoosableFileFilter(csvFilter);
        fileChooser.setAcceptAllFileFilterUsed(true);
        fileChooser.setFileFilter(csvFilter);
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        String defaultFileName = (String) this.tablesDropdownList.getSelectedItem();
        fileChooser.setSelectedFile(new File(defaultFileName));
        int choice = fileChooser.showSaveDialog((Component) evt.getSource()); //TODO
        if (JFileChooser.APPROVE_OPTION == choice) {
            File file = fileChooser.getSelectedFile();
            if (file.exists() && FilenameUtils.getExtension(file.getName()).equalsIgnoreCase("csv")) {
                if (JOptionPane.YES_OPTION == JOptionPane.showConfirmDialog(this,
                        Bundle.SQLiteViewer_csvExport_confirm_msg(),
                        Bundle.SQLiteViewer_csvExport_title(),
                        JOptionPane.YES_NO_OPTION)) {
                } else {
                    return;
                }
            }

            exportTableToCsv(file);
        }
    }//GEN-LAST:event_exportCsvButtonActionPerformed

    private void jTableDataPanelComponentHidden(java.awt.event.ComponentEvent evt) {//GEN-FIRST:event_jTableDataPanelComponentHidden
        // TODO add your handling code here:
    }//GEN-LAST:event_jTableDataPanelComponentHidden

    private void tablesDropdownListActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_tablesDropdownListActionPerformed
        JComboBox<?> cb = (JComboBox<?>) evt.getSource();
        String tableName = (String) cb.getSelectedItem();
        if (null == tableName) {
            return;
        }
        WindowManager.getDefault().getMainWindow().setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
        selectTable(tableName);
        WindowManager.getDefault().getMainWindow().setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
    }//GEN-LAST:event_tablesDropdownListActionPerformed

    private void tablesDropdownListComponentHidden(java.awt.event.ComponentEvent evt) {//GEN-FIRST:event_tablesDropdownListComponentHidden
        // TODO add your handling code here:
    }//GEN-LAST:event_tablesDropdownListComponentHidden

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel currPageLabel;
    private javax.swing.JButton exportCsvButton;
    private javax.swing.JPanel jHdrPanel;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JPanel jTableDataPanel;
    private javax.swing.JButton nextPageButton;
    private javax.swing.JTextField numEntriesField;
    private javax.swing.JLabel numPagesLabel;
    private javax.swing.JButton prevPageButton;
    private javax.swing.JComboBox<String> tablesDropdownList;
    // End of variables declaration//GEN-END:variables

    @Override
    public List<String> getSupportedMIMETypes() {
        return Arrays.asList(SUPPORTED_MIMETYPES);
    }

    @Override
    public void setFile(AbstractFile file) {
        WindowManager.getDefault().getMainWindow().setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
        sqliteDbFile = file;
        try {
            actualFileName = Case.getCurrentCaseThrows().getModuleDirectory() + File.separator + "evtx" + File.separator +
                             file.getId() + "_" + file.getName() + ".db3";
        } catch (NoCurrentCaseException ex) {
            
        }
        initReader();
        processSQLiteFile();
        WindowManager.getDefault().getMainWindow().setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
    }

    @Override
    public Component getComponent() {
        return this;
    }

    @Override
    public void resetComponent() {
        tablesDropdownList.setEnabled(true);
        tablesDropdownList.removeAllItems();
        numEntriesField.setText("");

        try {
            viewReader.close();
        } catch (SQLiteTableReaderException ex) {
            //Could not successfully close the reader, nothing we can do to recover.
        }
        row = new LinkedHashMap<>();
        pageOfTableRows = new ArrayList<>();
        currentTableHeader = new ArrayList<>();
        viewReader = null;
        sqliteDbFile = null;
    }

    /**
     * Process the given SQLite DB file.
     */
    @NbBundle.Messages({
        "ExtViewer.comboBox.noTableEntry=No tables found",
        "ExtViewer.errorMessage.interrupted=The processing of the file was interrupted.",
        "ExtViewer.errorMessage.noCurrentCase=The case has been closed.",
        "ExtViewer.errorMessage.failedToExtractFile=The file could not be extracted from the data source.",
        "ExtViewer.errorMessage.failedToQueryDatabase=The database tables in the file could not be read.",
        "ExtViewer.errorMessage.failedToinitJDBCDriver=The JDBC driver for SQLite could not be loaded.",
        "# {0} - exception message", "ExtViewer.errorMessage.unexpectedError=An unexpected error occurred:\n{0).",})
    private void processSQLiteFile() {
        try {
            tablesDropdownList.removeAllItems();

            Collection<String> dbTablesMap = viewReader.getTableNames();
            if (dbTablesMap.isEmpty()) {
                tablesDropdownList.addItem(Bundle.SQLiteViewer_comboBox_noTableEntry());
                tablesDropdownList.setEnabled(false);
            } else {
                dbTablesMap.forEach((tableName) -> {
                    tablesDropdownList.addItem(tableName);
                });
            }
        } catch (SQLiteTableReaderException ex) {
            logger.log(Level.WARNING, String.format("Unable to get table names "
                    + "from sqlite file [%s] with id=[%d].", sqliteDbFile.getName(),
                    sqliteDbFile.getId(), ex.getMessage()));
            MessageNotifyUtil.Message.error(Bundle.SQLiteViewer_errorMessage_failedToQueryDatabase());
        }
    }

    @NbBundle.Messages({"# {0} - tableName",
        "ExtViewer.selectTable.errorText=Error getting row count for table: {0}"
    })
    private void selectTable(String tableName) {
        try {
            numRows = viewReader.getRowCount(tableName);
            numEntriesField.setText(numRows + " entries");

            currPage = 1;
            currPageLabel.setText(Integer.toString(currPage));
            numPagesLabel.setText(Integer.toString((numRows / ROWS_PER_PAGE) + 1));

            prevPageButton.setEnabled(false);

            if (numRows > 0) {
                exportCsvButton.setEnabled(true);
                nextPageButton.setEnabled(((numRows > ROWS_PER_PAGE)));
                readTable(tableName, (currPage - 1) * ROWS_PER_PAGE + 1, ROWS_PER_PAGE);
            } else {
                exportCsvButton.setEnabled(false);
                nextPageButton.setEnabled(false);

                currentTableHeader = new ArrayList<>();
                viewReader.read(tableName);
                Map<String, Object> columnRow = new LinkedHashMap<>();
                for (int i = 0; i < currentTableHeader.size(); i++) {
                    columnRow.put(currentTableHeader.get(i), "");
                }
                selectedTableView.setupTable(Collections.singletonList(columnRow));
            }
        } catch (SQLiteTableReaderException ex) {
            logger.log(Level.WARNING, String.format("Failed to load table %s " //NON-NLS
                    + "from DB file '%s' (objId=%d)", tableName, sqliteDbFile.getName(), //NON-NLS
                    sqliteDbFile.getId()), ex.getMessage());
            MessageNotifyUtil.Message.error(Bundle.SQLiteViewer_selectTable_errorText(tableName));
        }
    }

    @NbBundle.Messages({"# {0} - tableName",
        "ExtViewer.readTable.errorText=Error getting rows for table: {0}"})
    private void readTable(String tableName, int startRow, int numRowsToRead) {
        try {
            //If the table name has changed, then clear our table header. SQLiteTableReader
            //will also detect the table name has changed and begin reading it as if it
            //were a brand new table.
            if (!tableName.equals(prevTableName)) {
                prevTableName = tableName;
            }
            currentTableHeader = new ArrayList<>();
            viewReader.read(tableName, numRowsToRead, startRow - 1);
            selectedTableView.setupTable(pageOfTableRows);
            pageOfTableRows = new ArrayList<>();
        } catch (SQLiteTableReaderException ex) {
            logger.log(Level.WARNING, String.format("Failed to read table %s from DB file '%s' " //NON-NLS
                    + "(objId=%d) starting at row [%d] and limit [%d]", //NON-NLS
                    tableName, sqliteDbFile.getName(), sqliteDbFile.getId(),
                    startRow - 1, numRowsToRead), ex.getMessage());
            MessageNotifyUtil.Message.error(Bundle.SQLiteViewer_readTable_errorText(tableName));
        }
    }

    /**
     * Creates a new SQLiteTableReader. This class will iterate through the
     * table row by row and pass each value to the correct function based on its
     * data type. For our use, we want to define an action when encountering
     * column names and an action for all other data types.
     */
    private void initReader() {
        viewReader = new SQLiteTableReader.Builder(sqliteDbFile, actualFileName)
                .forAllColumnNames((columnName) -> {
                    currentTableHeader.add(columnName);
                })
                .forAllTableValues(getForAllStrategy()).build();
    }

    /**
     * For every database value we encounter on our read of the table do the
     * following: 1) Get the string representation of the value 2) Collect the
     * values until we have a full database row. 3) If we have the full row,
     * write it to the UI.
     *
     * rowIndex is purely for indicating if we have read the full row.
     *
     * @return Consumer that will perform the actions above. When the
     *         SQLiteTableReader is reading, values will be passed to this
     *         consumer.
     */
    private Consumer<Object> getForAllStrategy() {
        return new Consumer<Object>() {
            private int rowIndex = 0;

            @Override
            public void accept(Object t) {
                rowIndex++;
                String objectStr = (t instanceof byte[]) ? "BLOB Data not shown"
                        : Objects.toString(t, "");

                row.put(currentTableHeader.get(rowIndex - 1), objectStr);

                //If we have built up a full database row, then add it to our page
                //of rows to be displayed in the UI.
                if (rowIndex == currentTableHeader.size()) {
                    pageOfTableRows.add(row);
                    row = new LinkedHashMap<>();
                }
                rowIndex %= currentTableHeader.size();
            }

        };
    }

    private int totalColumnCount;

    @NbBundle.Messages({"ExtViewer.exportTableToCsv.write.errText=Failed to export table content to csv file.",
        "ExtViewer.exportTableToCsv.FileName=File name: ",
        "ExtViewer.exportTableToCsv.TableName=Table name: "
    })
    private void exportTableToCsv(File file) {
        File csvFile = new File(file.toString() + ".csv");
        String tableName = (String) this.tablesDropdownList.getSelectedItem();
        try (FileOutputStream out = new FileOutputStream(csvFile, false)) {
            try (SQLiteTableReader sqliteStream = new SQLiteTableReader.Builder(sqliteDbFile)
                    .forAllColumnNames(getColumnNameCSVStrategy(out))
                    .forAllTableValues(getForAllCSVStrategy(out)).build()) {
                totalColumnCount = sqliteStream.getColumnCount(tableName);
                sqliteStream.read(tableName);
            }
        } catch (IOException | SQLiteTableReaderException | RuntimeException ex) {
            logger.log(Level.WARNING, String.format("Failed to export table [%s]"
                    + " to CSV in sqlite file '%s' (objId=%d)", tableName, sqliteDbFile.getName(),
                    sqliteDbFile.getId()), ex.getMessage()); //NON-NLS
            MessageNotifyUtil.Message.error(Bundle.SQLiteViewer_exportTableToCsv_write_errText());
        }
    }

    /**
     * For every column name we encounter on our read of the table do the
     * following: 1) Format the name so that it is comma seperated 2) Write the
     * value to the output stream.
     *
     * columnIndex is purely for keeping track of where the column name is in
     * the table so the value can be correctly formatted.
     *
     * @param out Output stream that this database table is being written to.
     *
     * @return Consumer that will perform the actions above. When the
     *         SQLiteTableReader is reading, values will be passed to this
     *         consumer.
     */
    private Consumer<String> getColumnNameCSVStrategy(FileOutputStream out) {
        return new Consumer<String>() {
            private int columnIndex = 0;

            @Override
            public void accept(String columnName) {
                columnIndex++;
                String csvString = columnName;
                //Format the value to adhere to the format of a CSV file
                if (columnIndex == 1) {
                    csvString = "\"" + csvString + "\"";
                } else {
                    csvString = ",\"" + csvString + "\"";
                }
                if (columnIndex == totalColumnCount) {
                    csvString += "\n";
                }

                try {
                    out.write(csvString.getBytes());
                } catch (IOException ex) {
                    /*
                     * If we can no longer write to the output stream, toss a
                     * runtime exception to get out of iteration. We explicitly
                     * catch this in exportTableToCsv() above.
                     */
                    throw new RuntimeException(ex);
                }
            }
        };
    }

    /**
     * For every database value we encounter on our read of the table do the
     * following: 1) Get the string representation of the value 2) Format it so
     * that it adheres to the CSV format. 3) Write it to the output file.
     *
     * rowIndex is purely for keeping track of positioning of the database value
     * in the row, so that it can be properly formatted.
     *
     * @param out Output file
     *
     * @return Consumer that will perform the actions above. When the
     *         SQLiteTableReader is reading, values will be passed to this
     *         consumer.
     */
    private Consumer<Object> getForAllCSVStrategy(FileOutputStream out) {
        return new Consumer<Object>() {
            private int rowIndex = 0;

            @Override
            public void accept(Object tableValue) {
                rowIndex++;
                //Substitute string representation of blob with placeholder text.
                //Automatically wrap the value in quotes in case it contains commas.
                String objectStr = (tableValue instanceof byte[])
                        ? "BLOB Data not shown" : Objects.toString(tableValue, "");
                objectStr = "\"" + objectStr + "\"";

                if (rowIndex > 1) {
                    objectStr = "," + objectStr;
                }
                if (rowIndex == totalColumnCount) {
                    objectStr += "\n";
                }

                try {
                    out.write(objectStr.getBytes());
                } catch (IOException ex) {
                    /*
                     * If we can no longer write to the output stream, toss a
                     * runtime exception to get out of iteration. We explicitly
                     * catch this in exportTableToCsv() above.
                     */
                    throw new RuntimeException(ex);
                }
                rowIndex %= totalColumnCount;
            }
        };
    }

    @Override
    public boolean isSupported(AbstractFile file) {
        if (file == null) {
            return false;
        }
        if (file.getSize() == 0) {
            return false;
        }

        if (file.getNameExtension().toLowerCase().startsWith(LOG_FILE_EXTENSION)) {
            return true;
        }
        
        return false;

    }
}
