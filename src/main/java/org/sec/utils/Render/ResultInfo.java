package org.sec.Utils.Render;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class ResultInfo {
    private String anomalyDegree;
    private String jspFilePath;
    private String details = "";

    private List<String> msgList = new ArrayList<>();

    public String getJspFilePath() {
        return jspFilePath;
    }

    public String getAnomalyDegree() {
        return anomalyDegree;
    }

    public String getDetails() {
        return details;
    }

    public List<String> getMsgList() {
        return msgList;
    }

    public void setJspFilePath(String jspFilePath) {
        this.jspFilePath = jspFilePath;
    }
    public void setAnomalyDegree(String anomalyDegree) {
        this.anomalyDegree = anomalyDegree;
    }

    public void setDetails(String details){
        this.details = details;
    }
    public void setMsgList(List<String> msgList){
        this.msgList = msgList;
    }

//    @Override
//    public String toString() {
//        StringBuilder sb = new StringBuilder();
//        sb.append(this.anomalyDegree);
//        sb.append("\n");
//        for (String s : details) {
//            sb.append("\t");
//            sb.append(s);
//            sb.append("\n");
//        }
//        return sb.toString();
//    }

//    @Override
//    public boolean equals(Object o) {
//        if (this == o) return true;
//        if (o == null || getClass() != o.getClass()) return false;
//        ResultInfo that = (ResultInfo) o;
//        boolean first = Objects.equals(anomalyDegree, that.anomalyDegree);
//        boolean second = Objects.equals(jspFilePath, that.jspFilePath);
//        boolean third = true;
//        if (details.size() == that.details.size()) {
//            for (int i = 0; i < details.size(); i++) {
//                if (!details.get(i).equals(that.details.get(i))) {
//                    third = false;
//                    break;
//                }
//            }
//            return first & second & third;
//        } else {
//            return false;
//        }
//    }

    @Override
    public int hashCode() {
        return Objects.hash(anomalyDegree, jspFilePath, details);
    }
}

