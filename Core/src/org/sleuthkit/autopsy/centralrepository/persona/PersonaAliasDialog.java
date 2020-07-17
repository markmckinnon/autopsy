/*
 * Central Repository
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
package org.sleuthkit.autopsy.centralrepository.persona;

import javax.swing.JDialog;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import org.apache.commons.lang.StringUtils;
import org.openide.util.NbBundle.Messages;
import org.openide.windows.WindowManager;
import org.sleuthkit.autopsy.centralrepository.datamodel.Persona;

/**
 * Configuration dialog for adding aliases to a persona.
 */
@SuppressWarnings("PMD.SingularField") // UI widgets cause lots of false positives
public class PersonaAliasDialog extends JDialog {

    private static final long serialVersionUID = 1L;

    private final PersonaDetailsPanel pdp;

    private PersonaDetailsPanel.PAlias currentAlias = null;

    /**
     * Creates new add alias dialog
     */
    @Messages({"PersonaAliasDialog.title.text=Add Alias",})
    public PersonaAliasDialog(PersonaDetailsPanel pdp) {
        super(SwingUtilities.windowForComponent(pdp),
                Bundle.PersonaAliasDialog_title_text(),
                ModalityType.APPLICATION_MODAL);
        this.pdp = pdp;

        initComponents();
        display();
    }

    PersonaAliasDialog(PersonaDetailsPanel pdp, PersonaDetailsPanel.PAlias pa) {
        super(SwingUtilities.windowForComponent(pdp),
                Bundle.PersonaAliasDialog_title_text(),
                ModalityType.APPLICATION_MODAL);
        this.pdp = pdp;

        initComponents();
        currentAlias = pa;
        confidenceComboBox.setSelectedItem(pa.confidence);
        justificationTextField.setText(pa.justification);
        aliasTextField.setText(pa.alias);

        aliasTextField.setEnabled(false);

        display();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        settingsPanel = new javax.swing.JPanel();
        aliasLbl = new javax.swing.JLabel();
        aliasTextField = new javax.swing.JTextField();
        confidenceLbl = new javax.swing.JLabel();
        confidenceComboBox = new javax.swing.JComboBox<>();
        justificationLbl = new javax.swing.JLabel();
        justificationTextField = new javax.swing.JTextField();
        cancelBtn = new javax.swing.JButton();
        okBtn = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setResizable(false);

        settingsPanel.setBorder(javax.swing.BorderFactory.createEtchedBorder());

        org.openide.awt.Mnemonics.setLocalizedText(aliasLbl, org.openide.util.NbBundle.getMessage(PersonaAliasDialog.class, "PersonaAliasDialog.aliasLbl.text")); // NOI18N

        aliasTextField.setText(org.openide.util.NbBundle.getMessage(PersonaAliasDialog.class, "PersonaAliasDialog.aliasTextField.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(confidenceLbl, org.openide.util.NbBundle.getMessage(PersonaAliasDialog.class, "PersonaAliasDialog.confidenceLbl.text")); // NOI18N

        confidenceComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(org.sleuthkit.autopsy.centralrepository.datamodel.Persona.Confidence.values()));

        org.openide.awt.Mnemonics.setLocalizedText(justificationLbl, org.openide.util.NbBundle.getMessage(PersonaAliasDialog.class, "PersonaAliasDialog.justificationLbl.text")); // NOI18N

        justificationTextField.setText(org.openide.util.NbBundle.getMessage(PersonaAliasDialog.class, "PersonaAliasDialog.justificationTextField.text")); // NOI18N

        javax.swing.GroupLayout settingsPanelLayout = new javax.swing.GroupLayout(settingsPanel);
        settingsPanel.setLayout(settingsPanelLayout);
        settingsPanelLayout.setHorizontalGroup(
            settingsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(settingsPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(settingsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(settingsPanelLayout.createSequentialGroup()
                        .addComponent(aliasLbl)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(aliasTextField))
                    .addGroup(settingsPanelLayout.createSequentialGroup()
                        .addComponent(justificationLbl)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(justificationTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 262, Short.MAX_VALUE))
                    .addGroup(settingsPanelLayout.createSequentialGroup()
                        .addComponent(confidenceLbl)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(confidenceComboBox, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                .addContainerGap())
        );
        settingsPanelLayout.setVerticalGroup(
            settingsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(settingsPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(settingsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(aliasLbl)
                    .addComponent(aliasTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(settingsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(confidenceComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(confidenceLbl))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(settingsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(justificationTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(justificationLbl))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        org.openide.awt.Mnemonics.setLocalizedText(cancelBtn, org.openide.util.NbBundle.getMessage(PersonaAliasDialog.class, "PersonaAliasDialog.cancelBtn.text_1")); // NOI18N
        cancelBtn.setMaximumSize(new java.awt.Dimension(79, 23));
        cancelBtn.setMinimumSize(new java.awt.Dimension(79, 23));
        cancelBtn.setPreferredSize(new java.awt.Dimension(79, 23));
        cancelBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelBtnActionPerformed(evt);
            }
        });

        org.openide.awt.Mnemonics.setLocalizedText(okBtn, org.openide.util.NbBundle.getMessage(PersonaAliasDialog.class, "PersonaAliasDialog.okBtn.text_1")); // NOI18N
        okBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                okBtnActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(okBtn)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(cancelBtn, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
            .addComponent(settingsPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

        layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {cancelBtn, okBtn});

        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(settingsPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(okBtn)
                    .addComponent(cancelBtn, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void display() {
        this.setLocationRelativeTo(WindowManager.getDefault().getMainWindow());
        setVisible(true);
    }

    @Messages({
        "PersonaAliasDialog_empty_Title=Empty alias",
        "PersonaAliasDialog_empty_msg=An alias cannot be empty.",
        "PersonaAliasDialog_dup_Title=Alias add failure",
        "PersonaAliasDialog_dup_msg=This alias has already been added to this persona.",})
    private void okBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_okBtnActionPerformed
        if (StringUtils.isBlank(aliasTextField.getText())) {
            JOptionPane.showMessageDialog(this,
                    Bundle.PersonaAliasDialog_empty_msg(),
                    Bundle.PersonaAliasDialog_empty_Title(),
                    JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (StringUtils.isBlank(justificationTextField.getText())) {
            JOptionPane.showMessageDialog(this,
                    Bundle.PersonaDetailsPanel_empty_justification_msg(),
                    Bundle.PersonaDetailsPanel_empty_justification_Title(),
                    JOptionPane.ERROR_MESSAGE);
            return;
        }

        Persona.Confidence confidence = (Persona.Confidence) confidenceComboBox.getSelectedItem();
        String justification = justificationTextField.getText();

        if (currentAlias != null) {
            currentAlias.confidence = confidence;
            currentAlias.justification = justification;
            dispose();
        } else {
            if (pdp.addAlias(aliasTextField.getText(), justification, confidence)) {
                dispose();
            } else {
                JOptionPane.showMessageDialog(this,
                        Bundle.PersonaAliasDialog_dup_msg(),
                        Bundle.PersonaAliasDialog_dup_Title(),
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }//GEN-LAST:event_okBtnActionPerformed

    private void cancelBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelBtnActionPerformed
        dispose();
    }//GEN-LAST:event_cancelBtnActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel aliasLbl;
    private javax.swing.JTextField aliasTextField;
    private javax.swing.JButton cancelBtn;
    private javax.swing.JComboBox<org.sleuthkit.autopsy.centralrepository.datamodel.Persona.Confidence> confidenceComboBox;
    private javax.swing.JLabel confidenceLbl;
    private javax.swing.JLabel justificationLbl;
    private javax.swing.JTextField justificationTextField;
    private javax.swing.JButton okBtn;
    private javax.swing.JPanel settingsPanel;
    // End of variables declaration//GEN-END:variables
}