package org.sec.Form;

import com.formdev.flatlaf.FlatDarkLaf;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;
import org.sec.ImitateJVM.Constant;
import org.sec.ImitateJVM.DebugOption;
import org.sec.start.Application;
import org.sec.Utils.FileUtils;
import org.sec.Utils.stringUtils;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

public class JSPHunter {
    public static JSPHunter instance;
    private JPanel JSPHunterPanel;
    private JButton jarButton;
    private JPanel selectJarPanel;
    private JTextField jarPathTextField;
    private JLabel jarPathLabel;
    private JPanel configPanel;
    private JCheckBox DebugModeCheckBox;
    private JCheckBox InfoModeCheckBox;
    private JCheckBox DeleteModeCheckBox;
    private JButton relyButton;
    private JTextField relyPathTextField;
    private JLabel relyPathLabel;
    private JButton openStatin;
    private JButton StartScanButton;
    private JButton setOutputButton;
    private JTextField outputText;
    private JButton openOutputButton;
    private JPanel outputPanel;

    public static void start0() {
        FlatDarkLaf.setup();
        JFrame frame = new JFrame(Constant.versionNumber);
        instance = new JSPHunter();
        frame.setContentPane(instance.JSPHunterPanel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setJMenuBar(createMenuBar());
        frame.pack();
        frame.setVisible(true);
        instance.initAction();
    }

    private static JMenuBar createMenuBar() {
        JMenuBar menuBar = new JMenuBar();
        menuBar.add(createAboutMenu());
        return menuBar;
    }

    private static JMenu createAboutMenu() {
        JMenu aboutMenu = new JMenu("关于");
        JMenuItem workItem = new JMenuItem("它是如何工作的");
        workItem.addActionListener(e -> {
            JFrame frame = new JFrame("它是如何工作的");
            frame.setContentPane(new HowThisWork().workPanel);
            frame.setLocationRelativeTo(instance.JSPHunterPanel);
            frame.pack();
            frame.setVisible(true);
        });
        aboutMenu.add(workItem);
        JMenuItem helpPlate = new JMenuItem("使用帮助");
        helpPlate.addActionListener(e -> {
            JFrame frame = new JFrame("使用帮助");
            frame.setContentPane(new helpPlate().helpPlate);
            frame.setLocationRelativeTo(instance.JSPHunterPanel);
            frame.pack();
            frame.setVisible(true);
        });
        aboutMenu.add(helpPlate);
        return aboutMenu;
    }

    private void initAction() {
        // 示例输入
        jarPathTextField.setText("/Users/macmini/Environment/Tomcat/apache-tomcat-9.0.106/webapps/ROOT/");
        relyPathTextField.setText("/Users/macmini/Environment/Tomcat/apache-tomcat-9.0.106/lib");

        if (System.getProperty("os.name").toLowerCase().contains("windows")) {
            Constant.isWindows = true;
        } else if (System.getProperty("os.name").toLowerCase().contains("mac")) {
            Constant.isMac = true;
        } else Constant.isLinux = true;

//        DebugModeCheckBox.setSelected(false); // todo debug模式有bug,但是好像也不能算bug: 当使用newInstance时可以二次debug分析
//        InfoModeCheckBox.setSelected(false);
//        DeleteModeCheckBox.setSelected(false);

        choiceFile(jarButton, true);
        choiceFile(relyButton, false);

        setOutputButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            int option = fileChooser.showOpenDialog(new JFrame());
            if (option == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                String absPath = file.getAbsolutePath();
                if (!Files.exists(Paths.get(absPath))) {
                    JOptionPane.showMessageDialog(JSPHunterPanel, "目录并不存在");
                }
                Constant.outputPath = absPath + File.separator + "out" + File.separator + new SimpleDateFormat("yyyy.MM.dd.HH.mm").format(new Date()) + ".html";
                if (stringUtils.pathSecurityCheck(Constant.isWindows, Constant.outputPath, "\\.html"))
                    Constant.outputPath = "";
                outputText.setText(Constant.outputPath);
            }
        });

        openOutputButton.addActionListener(e -> {
            if (outputText.getText().isEmpty() || !new File(outputText.getText()).exists() || stringUtils.pathSecurityCheck(Constant.isWindows, outputText.getText(), "\\.html")) {
                JOptionPane.showMessageDialog(null, "想打开的文件不存在,或者不是 html 文件!", "错误提示", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            openOutput(outputText.getText());
        });

        openStatin.addActionListener(e -> {
            try {
                ProcessBuilder builder;
                if (Constant.isWindows) {
                    builder = new ProcessBuilder("cmd", "/c", "start", "notepad.exe", ".\\stainSource.txt");
                } else if (Constant.isMac) {
                    builder = new ProcessBuilder("open", "./stainSource.txt"); // macOS
                } else {
                    builder = new ProcessBuilder("xdg-open", "./stainSource.txt"); // Linux
                }
                builder.start(); // 无需处理流（短暂进程可忽略输出）
            } catch (IOException e1) {
                JOptionPane.showMessageDialog(null, "打开文件失败: " + e1.getMessage(),
                        "错误提示", JOptionPane.ERROR_MESSAGE); // 改为 ERROR 更醒目
            }
        });

        StartScanButton.addActionListener(e -> {
            if (jarPathTextField.getText().isEmpty()) {
                JOptionPane.showMessageDialog(JSPHunterPanel, "jar 目录不能为空");
                return;
            }
            if (relyPathTextField.getText().isEmpty()) {
                JOptionPane.showMessageDialog(JSPHunterPanel, "依赖 文件/目录不能为空,例子: D:\\Soft\\phpstudy_pro\\Extensions\\apache-tomcat-8.5.96\\lib");
                return;
            }
            Constant.dict = jarPathTextField.getText();
            Set<String> fileArray = new HashSet<>();
            FileUtils.readWebDir(Constant.dict, fileArray);
            if (fileArray.isEmpty()) {
                JOptionPane.showMessageDialog(JSPHunterPanel, "选择的 jar 目录不正确,例子: D:\\Soft\\phpstudy_pro\\Extensions\\apache-tomcat-8.5.96\\webapps\\ROOT");
                return;
            }
            DebugOption.userDebug = DebugModeCheckBox.isSelected();
            Constant.isOpenDeleteMode = DeleteModeCheckBox.isSelected();
            Constant.isOpenInfoMode = InfoModeCheckBox.isSelected();
            Constant.classPath = relyPathTextField.getText();

            String currentPath = new File(".").getAbsolutePath();
            currentPath = currentPath.substring(0, currentPath.length() - 1) + "out" + File.separator;
            String currentTimeString = new SimpleDateFormat("yyyy.MM.dd.HH.mm").format(new Date());
            outputText.setText(currentPath + currentTimeString + ".html");
            Constant.outputPath = outputText.getText();
            if (!FileUtils.createFile(Constant.outputPath)) {
                JOptionPane.showMessageDialog(null, "无法创建文件,请使用管理员权限创建打开 JSPHunter !", "错误提示", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            new Thread(() -> {
                try {
                    Application.analysis();
                } catch (IOException | ClassNotFoundException ex) {
                    throw new RuntimeException(ex);
                }
            }).start();
        });
    }

    public static void openOutput(String fileName) {
        try {
            ProcessBuilder builder = new ProcessBuilder();
            // 设置工作目录为文件所在目录（避免相对路径问题）
            File targetFile = new File(fileName);
            builder.directory(targetFile.getParentFile());

            if (Constant.isWindows) {
                builder.command("cmd", "/c", "start", "\"\"", targetFile.getName());
            } else if (Constant.isMac) {
                builder.command("open", targetFile.getName()); // macOS
            } else {
                builder.command("xdg-open", targetFile.getName()); // Linux
            }

            // 合并标准/错误流，避免阻塞
            builder.redirectErrorStream(true);
            Process process = builder.start();
            // 非阻塞等待（可选）
            new Thread(() -> {
                try { process.waitFor(); } catch (InterruptedException ignored) {}
            }).start();

        } catch (IOException e) {
            String errorMsg = "打开文件失败: " + e.getMessage();
            JOptionPane.showMessageDialog(null, errorMsg, "错误提示", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void choiceFile(JButton tempButton, boolean distinguish) {
        tempButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY); // 设置为选择目录模式

            int returnValue = fileChooser.showOpenDialog(new JFrame());
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                String absPath = selectedFile.getAbsolutePath();
                if (distinguish) { // 根据distinguish参数来判断逻辑
                    jarPathTextField.setText(absPath);
                } else {
                    relyPathTextField.setText(absPath);
                }
            }
        });
    }

    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        JSPHunterPanel = new JPanel();
        // 修改主面板布局为垂直BoxLayout [6,7](@ref)
        JSPHunterPanel.setLayout(new BoxLayout(JSPHunterPanel, BoxLayout.Y_AXIS));
        JSPHunterPanel.setMinimumSize(new Dimension(1000, 200));

        // 输入面板
        selectJarPanel = new JPanel();
        selectJarPanel.setLayout(new GridBagLayout()); // 使用GridBagLayout
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 10, 5, 10); // 设置间距
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.WEST;

        // 第一行：文件夹路径标签
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 0;
        jarPathLabel = new JLabel();
        jarPathLabel.setText("Folder Path :");
        selectJarPanel.add(jarPathLabel, gbc);

        // 第一行：文件夹路径文本框
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        jarPathTextField = new JTextField();
        jarPathTextField.setText("");
        jarPathTextField.setToolTipText("Tomcat文件夹路径");
        selectJarPanel.add(jarPathTextField, gbc);

        // 第一行：选择文件夹按钮
        gbc.gridx = 2;
        gbc.gridy = 0;
        gbc.weightx = 0;
        jarButton = new JButton();
        jarButton.setText("Input The Folder");
        jarButton.setToolTipText("输入想要扫描的Tomcat文件夹路径");
        selectJarPanel.add(jarButton, gbc);

        // 第二行：依赖路径标签
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0;
        relyPathLabel = new JLabel();
        relyPathLabel.setText("Rely Path :");
        selectJarPanel.add(relyPathLabel, gbc);

        // 第二行：依赖路径文本框
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.weightx = 1.0;
        relyPathTextField = new JTextField();
        relyPathTextField.setToolTipText("依赖文件夹路径");
        selectJarPanel.add(relyPathTextField, gbc);

        // 第二行：选择依赖按钮
        gbc.gridx = 2;
        gbc.gridy = 1;
        gbc.weightx = 0;
        relyButton = new JButton();
        relyButton.setText("Input The Rely Path");
        relyButton.setToolTipText("输入依赖文件夹路径");
        selectJarPanel.add(relyButton, gbc);

        selectJarPanel.setBorder(BorderFactory.createTitledBorder(null, "Input", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        JSPHunterPanel.add(selectJarPanel);

        // 添加垂直间距
        JSPHunterPanel.add(Box.createVerticalStrut(15));

        // 配置面板
        configPanel = new JPanel();
        configPanel.setLayout(new GridBagLayout());
        GridBagConstraints gbcConfig = new GridBagConstraints();
        gbcConfig.insets = new Insets(5, 10, 5, 10);
        gbcConfig.fill = GridBagConstraints.HORIZONTAL;
        gbcConfig.anchor = GridBagConstraints.WEST;

        // 第一列：Debug Mode
        gbcConfig.gridx = 0;
        gbcConfig.gridy = 0;
        gbcConfig.weightx = 1.0;
        DebugModeCheckBox = new JCheckBox();
        DebugModeCheckBox.setText("Debug Mode");
        DebugModeCheckBox.setToolTipText("是否开启debug模式,开启debug模式可得知污点流向");
        configPanel.add(DebugModeCheckBox, gbcConfig);

        // 第二列：Info Mode
        gbcConfig.gridx = 1;
        gbcConfig.gridy = 0;
        gbcConfig.weightx = 1.0;
        InfoModeCheckBox = new JCheckBox();
        InfoModeCheckBox.setText("Info Mode");
        InfoModeCheckBox.setToolTipText("是否开启info模式,尝试获取webshell的password");
        configPanel.add(InfoModeCheckBox, gbcConfig);

        // 第三列：Delete Mode
        gbcConfig.gridx = 2;
        gbcConfig.gridy = 0;
        gbcConfig.weightx = 1.0;
        DeleteModeCheckBox = new JCheckBox();
        DeleteModeCheckBox.setText("Delete Mode");
        DeleteModeCheckBox.setToolTipText("是否开启删除模式,开启后将自动删除恶意webshell,慎用");
        configPanel.add(DeleteModeCheckBox, gbcConfig);

        configPanel.setBorder(BorderFactory.createTitledBorder(null, "Config", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        JSPHunterPanel.add(configPanel);

        // 添加垂直间距
        JSPHunterPanel.add(Box.createVerticalStrut(15));

        // 输出面板
        outputPanel = new JPanel();
        outputPanel.setLayout(new GridBagLayout());
        GridBagConstraints gbcOutput = new GridBagConstraints();
        gbcOutput.insets = new Insets(5, 10, 5, 10);
        gbcOutput.fill = GridBagConstraints.HORIZONTAL;
        gbcOutput.anchor = GridBagConstraints.WEST;

        // 第一行：开始扫描按钮
        gbcOutput.gridx = 0;
        gbcOutput.gridy = 0;
        gbcOutput.weightx = 0;
        StartScanButton = new JButton();
        StartScanButton.setText("StartScan");
        StartScanButton.setToolTipText("开启扫描按钮,执行完毕后会自动弹出运行结果");
        outputPanel.add(StartScanButton, gbcOutput);

        // 第一行：设置输出按钮
        gbcOutput.gridx = 1;
        gbcOutput.gridy = 0;
        gbcOutput.weightx = 0;
        setOutputButton = new JButton();
        setOutputButton.setText("Set Output");
        setOutputButton.setToolTipText("设置输出目录");
        outputPanel.add(setOutputButton, gbcOutput);

        // 第一行：打开输出按钮
        gbcOutput.gridx = 2;
        gbcOutput.gridy = 0;
        gbcOutput.weightx = 0;
        openOutputButton = new JButton();
        openOutputButton.setText("Open Output");
        openOutputButton.setToolTipText("打开运行结果");
        outputPanel.add(openOutputButton, gbcOutput);

        // 第二行：输出路径文本框
        gbcOutput.gridx = 0;
        gbcOutput.gridy = 1;
        gbcOutput.gridwidth = 2; // 跨两列
        gbcOutput.weightx = 1.0;
        outputText = new JTextField();
        outputText.setToolTipText("输出文件的路径");
        outputPanel.add(outputText, gbcOutput);

        // 第二行：打开污点源文件按钮
        gbcOutput.gridx = 2;
        gbcOutput.gridy = 1;
        gbcOutput.gridwidth = 1;
        gbcOutput.weightx = 0;
        openStatin = new JButton();
        openStatin.setText("Open StainSource File");
        openStatin.setToolTipText("打开污点源文件");
        outputPanel.add(openStatin, gbcOutput);

        outputPanel.setBorder(BorderFactory.createTitledBorder(null, "Output", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        JSPHunterPanel.add(outputPanel);

        // 添加垂直胶水使组件顶部对齐
        JSPHunterPanel.add(Box.createVerticalGlue());
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return JSPHunterPanel;
    }

}
