package org.sec.Form;

import com.formdev.flatlaf.FlatDarkLaf;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;
import org.sec.ImitateJVM.Constant;
import org.sec.ImitateJVM.DebugOption;
import org.sec.Start.Application;
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
//        //todo 上线前把这两个初值删了
//        jarPathTextField.setText("D:\\Soft\\phpstudy_pro\\Extensions\\apache-tomcat-8.5.96\\webapps\\ROOT");
//        relyPathTextField.setText("C:\\Users\\14383\\Desktop\\lib");

        if (System.getProperty("os.name").toLowerCase().contains("windows")) {
            Constant.isWindows = true;
        }

//        DebugModeCheckBox.setSelected(false); // todo debug模式有bug,也不能算bug: 当使用newInstance时可以二次debug分析
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
            String cmd;
            if (Constant.isWindows) {
                cmd = "cmd /c start notepad.exe ." + File.separator + "stainSource.txt";
            } else {
                cmd = "xdg-open ." + File.separator + "stainSource.txt";
            }
            try {
                Runtime.getRuntime().exec(cmd);
            } catch (IOException e1) {
                JOptionPane.showMessageDialog(null, "打开文件失败: " + e1.getMessage(), "错误提示", JOptionPane.INFORMATION_MESSAGE);
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
        String cmd;
        if (Constant.isWindows) {
            cmd = "cmd /c start \"\" " + fileName;
        } else {
            cmd = "xdg-open " + fileName;
        }
        try {
            Runtime.getRuntime().exec(cmd);
        } catch (IOException e1) {
            JOptionPane.showMessageDialog(null, "打开文件失败: " + e1.getMessage(), "错误提示", JOptionPane.INFORMATION_MESSAGE);
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
        JSPHunterPanel.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));
        JSPHunterPanel.setMinimumSize(new Dimension(1000, 200));
        selectJarPanel = new JPanel();
        selectJarPanel.setLayout(new GridLayoutManager(4, 2, new Insets(0, 0, 0, 0), -1, -1));
        JSPHunterPanel.add(selectJarPanel);
        selectJarPanel.setBorder(BorderFactory.createTitledBorder(null, "Input", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        jarButton = new JButton();
        jarButton.setText("Input The Folder");
        jarButton.setToolTipText("输入想要扫描的Tomcat文件夹路径");
        selectJarPanel.add(jarButton, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(200, 30), null, 0, false));
        jarPathTextField = new JTextField();
        jarPathTextField.setText("");
        jarPathTextField.setToolTipText("Tomcat文件夹路径");
        selectJarPanel.add(jarPathTextField, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(200, 30), null, 0, false));
        jarPathLabel = new JLabel();
        jarPathLabel.setText("Folder Path :");
        selectJarPanel.add(jarPathLabel, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        relyButton = new JButton();
        relyButton.setText("Input The Rely Path");
        relyButton.setToolTipText("输入依赖文件夹路径");
        selectJarPanel.add(relyButton, new GridConstraints(2, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        relyPathTextField = new JTextField();
        relyPathTextField.setToolTipText("依赖文件夹路径");
        selectJarPanel.add(relyPathTextField, new GridConstraints(3, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        relyPathLabel = new JLabel();
        relyPathLabel.setText("Rely Path :");
        selectJarPanel.add(relyPathLabel, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        configPanel = new JPanel();
        configPanel.setLayout(new GridLayoutManager(3, 2, new Insets(0, 0, 0, 0), -1, -1));
        JSPHunterPanel.add(configPanel);
        configPanel.setBorder(BorderFactory.createTitledBorder(null, "Config", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        DebugModeCheckBox = new JCheckBox();
        DebugModeCheckBox.setText("Debug Mode");
        DebugModeCheckBox.setToolTipText("是否开启debug模式,开启debug模式可得知污点流向");
        configPanel.add(DebugModeCheckBox, new GridConstraints(0, 0, 1, 2, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        InfoModeCheckBox = new JCheckBox();
        InfoModeCheckBox.setText("Info Mode");
        InfoModeCheckBox.setToolTipText("是否开启info模式,尝试获取webshell的password");
        configPanel.add(InfoModeCheckBox, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        DeleteModeCheckBox = new JCheckBox();
        DeleteModeCheckBox.setText("Delete Mode");
        DeleteModeCheckBox.setToolTipText("是否开启删除模式,开启后将自动删除恶意webshell,慎用");
        configPanel.add(DeleteModeCheckBox, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        JSPHunterPanel.add(spacer1);
        outputPanel = new JPanel();
        outputPanel.setLayout(new GridLayoutManager(4, 2, new Insets(0, 0, 0, 0), -1, -1));
        JSPHunterPanel.add(outputPanel);
        outputPanel.setBorder(BorderFactory.createTitledBorder(null, "Output", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        StartScanButton = new JButton();
        StartScanButton.setText("StartScan");
        StartScanButton.setToolTipText("开启扫描按钮,执行完毕后会自动弹出运行结果");
        outputPanel.add(StartScanButton, new GridConstraints(3, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        setOutputButton = new JButton();
        setOutputButton.setText("Set Output");
        setOutputButton.setToolTipText("设置输出目录");
        outputPanel.add(setOutputButton, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        openOutputButton = new JButton();
        openOutputButton.setText("Open Output");
        openOutputButton.setToolTipText("打开运行结果");
        outputPanel.add(openOutputButton, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        outputText = new JTextField();
        outputText.setToolTipText("输出文件的路径");
        outputPanel.add(outputText, new GridConstraints(0, 1, 2, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        openStatin = new JButton();
        openStatin.setText("Open StainSource File");
        openStatin.setToolTipText("打开污点源文件");
        outputPanel.add(openStatin, new GridConstraints(2, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return JSPHunterPanel;
    }

}
