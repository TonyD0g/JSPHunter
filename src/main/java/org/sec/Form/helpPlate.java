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
        helpPlate.setLayout(new GridLayoutManager(4, 2, new Insets(0, 0, 0, 0), -1, -1));
        firstLabel = new JLabel();
        Font firstLabelFont = this.$$$getFont$$$("Consolas", -1, 20, firstLabel.getFont());
        if (firstLabelFont != null) firstLabel.setFont(firstLabelFont);
        firstLabel.setText("1.左侧Input模块上方输入可能存在Webshell的Tomcat扫描路径，比如:D:\\phpstudy_pro\\Extensions\\apache-tomcat-8.5.81\\webapps\\ROOT");
        helpPlate.add(firstLabel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        helpPlate.add(spacer1, new GridConstraints(0, 1, 4, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        secendLabel = new JLabel();
        Font secendLabelFont = this.$$$getFont$$$("Consolas", -1, 20, secendLabel.getFont());
        if (secendLabelFont != null) secendLabel.setFont(secendLabelFont);
        secendLabel.setText("2.左侧Input模块下方输入Tomcat的依赖包,比如: D:\\phpstudy_pro\\Extensions\\apache-tomcat-8.5.81\\lib");
        helpPlate.add(secendLabel, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        thirdLabel = new JLabel();
        Font thirdLabelFont = this.$$$getFont$$$("Consolas", -1, 20, thirdLabel.getFont());
        if (thirdLabelFont != null) thirdLabel.setFont(thirdLabelFont);
        thirdLabel.setText("3.中间的Config模块,可以自定义配置（可选项）");
        helpPlate.add(thirdLabel, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        fourLabel = new JLabel();
        Font fourLabelFont = this.$$$getFont$$$("Consolas", -1, 20, fourLabel.getFont());
        if (fourLabelFont != null) fourLabel.setFont(fourLabelFont);
        fourLabel.setText("4.右侧Output模块点击 \"StartScan\" 开始扫描");
        helpPlate.add(fourLabel, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
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