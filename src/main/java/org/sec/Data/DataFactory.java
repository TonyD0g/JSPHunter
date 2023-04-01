package org.sec.Data;

public interface DataFactory<T> {
    T parse(String[] fields);
    String[] serialize(T obj);
}
