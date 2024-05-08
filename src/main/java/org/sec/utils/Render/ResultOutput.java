package org.sec.Utils.Render;

import org.sec.ImitateJVM.Constant;
import org.sec.ImitateJVM.DebugOption;

import javax.swing.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

// 代码及其模板修改自 4ra1n 师傅的 https://github.com/4ra1n/code-inspector 库
public class ResultOutput {
    public static void write(String path, List<ResultInfo> results) {
        try {
            Set<ResultInfo> newResults = new LinkedHashSet<>(results);
            List<RenderData> renderData = new ArrayList<>();
            for (ResultInfo tempResultInfo : newResults) {
                RenderData tempRenderData = new RenderData();
                tempRenderData.setAnomalyDegree(tempResultInfo.getAnomalyDegree());
                tempRenderData.setJspFilePath(tempResultInfo.getJspFilePath());

                String setDetailsString;
                setDetailsString = String.format("<span class=\"badge badge-danger\">%s</span><br>", tempResultInfo.getDetails());

                if (Constant.isOpenDeleteMode && tempResultInfo.getAnomalyDegree().contains("恶意"))
                    setDetailsString = setDetailsString + "<span class=\"badge badge-danger\">由于你开启了 Delete 模式且该文件危险等级较高,因此该文件已被自动删除</span><br>";
                if (Constant.isOpenInfoMode) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("<span class=\"badge badge-warning\">获取到的所有字符串,连接密码可能存在其中,注意是一行一个:</span><br>" +
                            "<span class=\"badge badge-warning\">[技巧1: 关注不规则字符串和常用连接密码]</span><br>" +
                            "<span class=\"badge badge-warning\">[技巧2: 如果都试了都不行,且输出列表中存在base64编码的数据,可能密码在base64编码的数据里,需要人工进一步分析]</span><br>");
                    setDetailsString = traverseOutput(tempResultInfo, sb, setDetailsString);
                    List<String> nullMsgList = new ArrayList<>();
                    tempResultInfo.setMsgList(nullMsgList);
                }
                if (DebugOption.userDebug && !tempResultInfo.getMsgList().isEmpty())
                    setDetailsString = traverseOutput(tempResultInfo, new StringBuilder(), setDetailsString);
                tempRenderData.setDetails(setDetailsString);

                renderData.add(tempRenderData);
            }
            renderHtml(Paths.get(path), renderData);
        } catch (Exception ignored) {
        }
    }

    public static String traverseOutput(ResultInfo tempResultInfo, StringBuilder sb, String setDetailsString) {
        for (String c : tempResultInfo.getMsgList()) {
            sb.append(c);
            sb.append("<br>");
        }
        String detail = sb.toString();
        setDetailsString = setDetailsString +
                "<br>" + detail.substring(0, detail.length() - 4);
        return setDetailsString;
    }

    public static void renderHtml(Path savePath, List<RenderData> dataList) {
        byte[] prefix = readBytesFromIs(ResultOutput.class.getClassLoader().getResourceAsStream("prefix"));
        byte[] suffix = readBytesFromIs(ResultOutput.class.getClassLoader().getResourceAsStream("suffix"));
        if (prefix == null || prefix.length == 0 || suffix == null || suffix.length == 0) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        int index = 0;
        if (dataList == null) {
            return;
        }
        for (RenderData renderData : dataList) {
            index++;
            // 根据危险等级改字体颜色,恶意为红色,可疑为黄色
            if (renderData.getAnomalyDegree().contains("恶意")) {
                renderData.setAnomalyDegree(String.format("<td><span class=\"badge badge-danger\">%s</span></td>\n", renderData.getAnomalyDegree()));
            } else {
                renderData.setAnomalyDegree(String.format("<td><span class=\"badge badge-warning\">%s</span></td>\n", renderData.getAnomalyDegree()));
            }
            String temp = String.format("<tr>\n" +
                            "<th scope=\"row\">%s</th>\n" +
                            "%s" +
                            "<td><span class=\"badge badge-warning\">%s</span></td>\n" +
                            "<td>%s</td></tr>", index, renderData.getAnomalyDegree(),
                    renderData.getJspFilePath(), renderData.getDetails());
            sb.append(temp);
        }
        String data = sb.toString();
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8); // 使用UTF-8编码转换字符串为字节数组
        byte[] total = new byte[prefix.length + suffix.length + dataBytes.length];
        System.arraycopy(prefix, 0, total, 0, prefix.length);
        System.arraycopy(dataBytes, 0, total, prefix.length, dataBytes.length);
        System.arraycopy(suffix, 0, total, prefix.length + dataBytes.length, suffix.length);
        try {
            Files.write(savePath, total);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(null, "打开文件失败: " + e.getMessage(), "错误提示", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    public static byte[] readBytesFromIs(InputStream is) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            int nRead;
            byte[] data = new byte[16384];
            while ((nRead = is.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, nRead);
            }
            return buffer.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
