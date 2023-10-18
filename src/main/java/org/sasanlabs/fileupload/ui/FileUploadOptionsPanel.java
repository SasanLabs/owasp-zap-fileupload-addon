/**
 * Copyright 2023 SasanLabs
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sasanlabs.fileupload.ui;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.TitledBorder;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.sasanlabs.fileupload.configuration.FileUploadConfiguration;
import org.sasanlabs.fileupload.i18n.FileUploadI18n;

/**
 * FileUpload options panel for specifying settings which are used by {@code FileUploadScanRule} for
 * finding vulnerabilities related to FileUpload functionality in the applications.
 *
 * @author KSASAN preetkaran20@gmail.com
 * @since 1.0.0
 */
public class FileUploadOptionsPanel extends AbstractParamPanel {
    private static final long serialVersionUID = 1L;

    private JScrollPane settingsScrollPane;
    private JPanel footerPanel;

    // UI components
    private JTextField staticLocationConfigurationURIRegex;
    private JTextField dynamicLocationConfigurationURIRegex;
    private JTextField parseResponseStartIdentifier;
    private JTextField parseResponseEndIdentifier;

    private JCheckBox sendRequestsAfterFindingVulnerability;

    public FileUploadOptionsPanel() {
        super();
        this.setName(FileUploadI18n.getMessage("fileupload.settings.title"));
        this.setLayout(new BorderLayout());
        JPanel settingsPanel = new JPanel();
        settingsPanel.setLayout(new BoxLayout(settingsPanel, BoxLayout.Y_AXIS));
        settingsScrollPane =
                new JScrollPane(
                        settingsPanel,
                        ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                        ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        this.add(settingsScrollPane, BorderLayout.NORTH);
        footerPanel = new JPanel();
        this.add(footerPanel, BorderLayout.SOUTH);
        footerPanel.setLayout(new FlowLayout(FlowLayout.CENTER, 0, 0));
        init(settingsPanel);
    }

    private void init(JPanel settingsPanel) {
        settingsPanel.add(uriLocatorConfiguration());
        settingsPanel.add(buildSendRequestsAfterFindingVulnerabilityCheckbox());
        footerPanel.add(getResetButton());
    }

    private JLabel buildSendRequestsAfterFindingVulnerabilityCheckbox() {
        JLabel SendRequestsAfterFindingVulnerabilityLabel =
                new JLabel(
                        FileUploadI18n.getMessage(
                                "fileupload.settings.checkbox.sendrequestsaftervulnerability"));

        sendRequestsAfterFindingVulnerability = new JCheckBox();
        SendRequestsAfterFindingVulnerabilityLabel.add(sendRequestsAfterFindingVulnerability);

        return SendRequestsAfterFindingVulnerabilityLabel;
    }

    private JButton getResetButton() {
        JButton resetButton = new JButton();
        resetButton.setText(FileUploadI18n.getMessage("fileupload.settings.button.reset"));
        resetButton.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        resetOptionsPanel();
                    }
                });
        return resetButton;
    }

    private JPanel staticURILocatorConfiguration() {
        GridBagLayout gridBagLayout = new GridBagLayout();
        JPanel staticLocationConfigurationPanel = new JPanel();
        staticLocationConfigurationPanel.setLayout(gridBagLayout);
        TitledBorder staticLocationConfigurationPanelBorder =
                new TitledBorder(
                        FileUploadI18n.getMessage(
                                "fileupload.settings.urilocator.staticlocation.title"));
        staticLocationConfigurationPanel.setBorder(staticLocationConfigurationPanelBorder);
        GridBagConstraints staticLocationConfigurationGridBagConstriants = getGridBagConstraints();
        JLabel uriRegexLabel =
                new JLabel(
                        FileUploadI18n.getMessage(
                                "fileupload.settings.urilocator.staticlocation.uriregex"));
        staticLocationConfigurationPanel.add(
                uriRegexLabel, staticLocationConfigurationGridBagConstriants);
        staticLocationConfigurationGridBagConstriants.gridx++;
        staticLocationConfigurationURIRegex = new JTextField();
        staticLocationConfigurationURIRegex.setColumns(15);
        staticLocationConfigurationPanel.add(
                staticLocationConfigurationURIRegex, staticLocationConfigurationGridBagConstriants);
        staticLocationConfigurationGridBagConstriants.gridy++;
        staticLocationConfigurationGridBagConstriants.gridx = 0;
        return staticLocationConfigurationPanel;
    }

    private JPanel dynamicURILocatorConfiguration() {
        TitledBorder dynamicLocationConfigurationPanelBorder =
                new TitledBorder(
                        FileUploadI18n.getMessage(
                                "fileupload.settings.urilocator.dynamiclocation.title"));
        JPanel dynamicLocationConfigurationPanel = new JPanel();
        GridBagLayout gridBagLayout = new GridBagLayout();
        dynamicLocationConfigurationPanel.setLayout(gridBagLayout);
        dynamicLocationConfigurationPanel.setBorder(dynamicLocationConfigurationPanelBorder);
        GridBagConstraints dynamicLocationConfigurationGridBagConstriants = getGridBagConstraints();
        JLabel dynamicLocationConfigurationURIRegexLabel =
                new JLabel(
                        FileUploadI18n.getMessage(
                                "fileupload.settings.urilocator.dynamiclocation.uriregex"));
        dynamicLocationConfigurationPanel.add(
                dynamicLocationConfigurationURIRegexLabel,
                dynamicLocationConfigurationGridBagConstriants);
        dynamicLocationConfigurationGridBagConstriants.gridx++;
        dynamicLocationConfigurationURIRegex = new JTextField();
        dynamicLocationConfigurationURIRegex.setColumns(15);
        dynamicLocationConfigurationPanel.add(
                dynamicLocationConfigurationURIRegex,
                dynamicLocationConfigurationGridBagConstriants);
        dynamicLocationConfigurationGridBagConstriants.gridy++;
        dynamicLocationConfigurationGridBagConstriants.gridx = 0;
        return dynamicLocationConfigurationPanel;
    }

    private JPanel parseResponseConfiguration() {
        TitledBorder parseResponseConfigurationPanelBorder =
                new TitledBorder(
                        FileUploadI18n.getMessage(
                                "fileupload.settings.urilocator.parseresponseconfiguration.title"));
        JPanel parseResponseConfigurationPanel = new JPanel();
        GridBagLayout gridBagLayout = new GridBagLayout();
        parseResponseConfigurationPanel.setLayout(gridBagLayout);
        parseResponseConfigurationPanel.setBorder(parseResponseConfigurationPanelBorder);
        GridBagConstraints parseResponseConfigurationGridBagConstriants = getGridBagConstraints();

        JLabel parseResponseConfigurationStartIdentifierLabel =
                new JLabel(
                        FileUploadI18n.getMessage(
                                "fileupload.settings.urilocator.parseresponseconfiguration.startidentifer"));
        parseResponseConfigurationPanel.add(
                parseResponseConfigurationStartIdentifierLabel,
                parseResponseConfigurationGridBagConstriants);
        parseResponseConfigurationGridBagConstriants.gridx++;
        parseResponseStartIdentifier = new JTextField();
        dynamicLocationConfigurationURIRegex.setColumns(15);
        parseResponseConfigurationPanel.add(
                parseResponseStartIdentifier, parseResponseConfigurationGridBagConstriants);
        parseResponseConfigurationGridBagConstriants.gridy++;
        parseResponseConfigurationGridBagConstriants.gridx = 0;

        JLabel parseResponseConfigurationEndIdentifierLabel =
                new JLabel(
                        FileUploadI18n.getMessage(
                                "fileupload.settings.urilocator.parseresponseconfiguration.endidentifer"));
        parseResponseConfigurationPanel.add(
                parseResponseConfigurationEndIdentifierLabel,
                parseResponseConfigurationGridBagConstriants);
        parseResponseConfigurationGridBagConstriants.gridx++;
        parseResponseEndIdentifier = new JTextField();
        dynamicLocationConfigurationURIRegex.setColumns(15);
        parseResponseConfigurationPanel.add(
                parseResponseEndIdentifier, parseResponseConfigurationGridBagConstriants);
        parseResponseConfigurationGridBagConstriants.gridy++;
        parseResponseConfigurationGridBagConstriants.gridx = 0;
        return parseResponseConfigurationPanel;
    }

    private JPanel uriLocatorConfiguration() {
        JPanel uriLocatorConfigurationPanel = new JPanel();
        uriLocatorConfigurationPanel.setSize(uriLocatorConfigurationPanel.getPreferredSize());
        GridBagLayout gridBagLayout = new GridBagLayout();
        uriLocatorConfigurationPanel.setLayout(gridBagLayout);
        GridBagConstraints gridBagConstraints = getGridBagConstraints();

        TitledBorder uriLocatorPanelBorder =
                new TitledBorder(FileUploadI18n.getMessage("fileupload.settings.urilocator.title"));
        uriLocatorConfigurationPanel.setBorder(uriLocatorPanelBorder);

        // Static Configuration
        uriLocatorConfigurationPanel.add(this.staticURILocatorConfiguration(), gridBagConstraints);
        gridBagConstraints.gridy++;
        // Dynamic Configuration
        uriLocatorConfigurationPanel.add(this.dynamicURILocatorConfiguration(), gridBagConstraints);
        gridBagConstraints.gridy++;
        // Parse Response Configuration
        uriLocatorConfigurationPanel.add(this.parseResponseConfiguration(), gridBagConstraints);
        gridBagConstraints.gridy++;
        return uriLocatorConfigurationPanel;
    }

    public static GridBagConstraints getGridBagConstraints() {
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.fill = GridBagConstraints.BOTH;
        gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.gridx = 0;
        gridBagConstraints.weightx = 1.0D;
        gridBagConstraints.weighty = 1.0D;
        return gridBagConstraints;
    }

    /** Resets entire panel to default values. */
    private void resetOptionsPanel() {
        staticLocationConfigurationURIRegex.setText("");
        dynamicLocationConfigurationURIRegex.setText("");
        parseResponseStartIdentifier.setText("");
        parseResponseEndIdentifier.setText("");
        sendRequestsAfterFindingVulnerability.setSelected(false);
    }

    @Override
    public void initParam(Object optionParams) {
        this.resetOptionsPanel();
        FileUploadConfiguration fileUploadConfiguration =
                ((OptionsParam) optionParams).getParamSet(FileUploadConfiguration.class);
        staticLocationConfigurationURIRegex.setText(
                fileUploadConfiguration.getStaticLocationURIRegex());
        dynamicLocationConfigurationURIRegex.setText(
                fileUploadConfiguration.getDynamicLocationURIRegex());
        parseResponseStartIdentifier.setText(
                fileUploadConfiguration.getParseResponseStartIdentifier());
        parseResponseEndIdentifier.setText(fileUploadConfiguration.getParseResponseEndIdentifier());
        sendRequestsAfterFindingVulnerability.setSelected(
                fileUploadConfiguration.getSendRequestsAfterFindingVulnerability());
    }

    @Override
    public void validateParam(Object optionParams) throws Exception {
        boolean isStaticUrlPresent =
                StringUtils.isNotEmpty(staticLocationConfigurationURIRegex.getText());
        boolean isDynamicUrlPresent =
                StringUtils.isNotEmpty(dynamicLocationConfigurationURIRegex.getText());
        boolean isStartIdentifierPresent =
                StringUtils.isNotEmpty(parseResponseStartIdentifier.getText());
        boolean isEndIdentifierPresent =
                StringUtils.isNotEmpty(parseResponseEndIdentifier.getText());

        if (isStaticUrlPresent
                && (isDynamicUrlPresent || isStartIdentifierPresent || isEndIdentifierPresent)) {
            throw new IllegalArgumentException(
                    FileUploadI18n.getMessage(
                            "fileupload.settings.alert.static.dynamicconfiguration.parseconfiguration.present"));
        } else if ((isStartIdentifierPresent && !isEndIdentifierPresent)
                || (!isStartIdentifierPresent && isEndIdentifierPresent)) {
            throw new IllegalArgumentException(
                    FileUploadI18n.getMessage(
                            "fileupload.settings.alert.invalid.httpresponseparseconfiguration"));
        } else if (isDynamicUrlPresent && !isStartIdentifierPresent) {
            throw new IllegalArgumentException(
                    FileUploadI18n.getMessage(
                            "fileupload.settings.alert.invalid.dynamicconfiguration.parseidentifier.not.present"));
        }
    }

    @Override
    public String getHelpIndex() {
        return "fileupload";
    }

    @Override
    public void saveParam(Object optionParams) {
        FileUploadConfiguration fileUploadConfiguration =
                ((OptionsParam) optionParams).getParamSet(FileUploadConfiguration.class);
        fileUploadConfiguration.setStaticLocationURIRegex(
                this.staticLocationConfigurationURIRegex.getText());
        fileUploadConfiguration.setDynamicLocationURIRegex(
                this.dynamicLocationConfigurationURIRegex.getText());
        fileUploadConfiguration.setParseResponseStartIdentifier(
                this.parseResponseStartIdentifier.getText());
        fileUploadConfiguration.setParseResponseEndIdentifier(
                this.parseResponseEndIdentifier.getText());
        fileUploadConfiguration.setSendRequestsAfterFindingVulnerability(
                this.sendRequestsAfterFindingVulnerability.isSelected());
    }
}
