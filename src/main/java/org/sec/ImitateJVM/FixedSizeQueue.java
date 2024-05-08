package org.sec.ImitateJVM;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.Queue;

public class FixedSizeQueue<E> extends LinkedList<E> {
    private int maxSize;

    public FixedSizeQueue(int maxSize) {
        this.maxSize = maxSize;
    }

    @Override
    public boolean add(E e) {
        super.add(e);
        while (size() > maxSize) {
            super.remove();
        }
        return true;
    }

    @Override
    public void addFirst(E e) {
        super.addFirst(e);
        while (size() > maxSize) {
            super.removeLast();
        }
    }

    @Override
    public void addLast(E e) {
        super.addLast(e);
        while (size() > maxSize) {
            super.removeFirst();
        }
    }
    public String[] getElementAtPosition(Queue<String[]> queue, int position) {
        Iterator<String[]> iterator = queue.iterator();
        int currentIndex = 0;
        while (iterator.hasNext() && currentIndex < position) {
            iterator.next();
            currentIndex++;
        }

        if (iterator.hasNext()) {
            return iterator.next();
        } else {
            return null;
        }
    }
}