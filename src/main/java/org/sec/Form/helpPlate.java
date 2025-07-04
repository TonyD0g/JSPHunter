package org.sec.Form;

import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;

import javax.swing.*;
import javax.swing.plaf.FontUIResource;
import javax.swing.text.StyleContext;
import java.awt.*;
import java.util.Locale;

public class helpPlate {
    public JPanel helpPlate;
    private JLabel firstLabel;
    private JLabel secendLabel;
    private JLabel thirdLabel;
    private JLabel fourLabel;

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
        helpPlate = new JPanel();
        // 使用 GridBagLayout 替代 GridLayoutManager
        helpPlate.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 15, 10, 15);  // 增加组件间距
        gbc.anchor = GridBagConstraints.WEST;      // 左对齐
        gbc.fill = GridBagConstraints.HORIZONTAL; // 水平填充

        // 标签1
        firstLabel = new JLabel();
        Font firstLabelFont = this.$$$getFont$$$("Consolas", -1, 20, firstLabel.getFont());
        if (firstLabelFont != null) firstLabel.setFont(firstLabelFont);
        firstLabel.setText("1.Input模块上方输入可能存在Webshell的Tomcat扫描路径，比如:D:\\phpstudy_pro\\Extensions\\apache-tomcat-8.5.81\\webapps\\ROOT");
        gbc.gridx = 0;
        gbc.gridy = 0;
        helpPlate.add(firstLabel, gbc);

        // 标签2
        secendLabel = new JLabel();
        Font secendLabelFont = this.$$$getFont$$$("Consolas", -1, 20, secendLabel.getFont());
        if (secendLabelFont != null) secendLabel.setFont(secendLabelFont);
        secendLabel.setText("2.Input模块下方输入Tomcat的依赖包,比如: D:\\phpstudy_pro\\Extensions\\apache-tomcat-8.5.81\\lib");
        gbc.gridy = 1;
        helpPlate.add(secendLabel, gbc);

        // 标签3
        thirdLabel = new JLabel();
        Font thirdLabelFont = this.$$$getFont$$$("Consolas", -1, 20, thirdLabel.getFont());
        if (thirdLabelFont != null) thirdLabel.setFont(thirdLabelFont);
        thirdLabel.setText("3.中间的Config模块,可以自定义配置（可选项）");
        gbc.gridy = 2;
        helpPlate.add(thirdLabel, gbc);

        // 标签4
        fourLabel = new JLabel();
        Font fourLabelFont = this.$$$getFont$$$("Consolas", -1, 20, fourLabel.getFont());
        if (fourLabelFont != null) fourLabel.setFont(fourLabelFont);
        fourLabel.setText("4.Output模块点击 \"StartScan\" 开始扫描");
        gbc.gridy = 3;
        helpPlate.add(fourLabel, gbc);
    }

    /**
     * @noinspection ALL
     */
    private Font $$$getFont$$$(String fontName, int style, int size, Font currentFont) {
        if (currentFont == null) return null;
        String resultName;
        if (fontName == null) {
            resultName = currentFont.getName();
        } else {
            Font testFont = new Font(fontName, Font.PLAIN, 10);
            if (testFont.canDisplay('a') && testFont.canDisplay('1')) {
                resultName = fontName;
            } else {
                resultName = currentFont.getName();
            }
        }
        Font font = new Font(resultName, style >= 0 ? style : currentFont.getStyle(), size >= 0 ? size : currentFont.getSize());
        boolean isMac = System.getProperty("os.name", "").toLowerCase(Locale.ENGLISH).startsWith("mac");
        Font fontWithFallback = isMac ? new Font(font.getFamily(), font.getStyle(), font.getSize()) : new StyleContext().getFont(font.getFamily(), font.getStyle(), font.getSize());
        return fontWithFallback instanceof FontUIResource ? fontWithFallback : new FontUIResource(fontWithFallback);
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return helpPlate;
    }

}
