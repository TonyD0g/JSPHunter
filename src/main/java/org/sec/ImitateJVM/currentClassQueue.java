package org.sec.ImitateJVM;

import java.util.LinkedList;
import java.util.Queue;

/**
 * 设置一个类队列,设置一个暂存类1和暂存类2字段,用于表示当前所处的类环境.如果执行的过程遇到了内部类，就更新暂存类1和2，将暂存类2顺延到暂存类1,内部类放置到暂存类2
 **/
public class currentClassQueue {
    public static String fatherClass; // 队首 暂存类1
    public static String sonClass; // 队尾 暂存类2
    public static Queue<String> queue = new LinkedList<>();

    /**
     * 初始化队列,初始化时只有 tmpClassSecond 为空
     **/
    public static void initClassQueue(String tmpClassFirst, String tmpClassSecond) {
        queue.add(tmpClassFirst);
        queue.add(tmpClassSecond);

        fatherClass = tmpClassFirst;
        sonClass = tmpClassSecond;
    }

    /**
     * 更新队列,如果有内部类就更新队列
     **/
    public static void updateClassQueue(String next) {
        queue.poll(); // 队首出队列  null jspServer cbd
        queue.add(next);    // 新的类进入队列
        getRelation();
    }

    /**
     * 根据队列来获取对应的类的层级关系
     **/
    public static void getRelation() {
        if (queue.size() == 2) {
            String[] array = queue.toArray(new String[0]);
            for (int i = 0; i < 2; i++) {
                fatherClass = array[0];
                sonClass = array[1];
            }
        }
    }
}
