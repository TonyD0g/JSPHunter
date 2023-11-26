package org.sec.Data;

/** 数据工厂,主要包含两个部分:  1.返回解析, 2.序列化数据 */
public interface DataFactory<T> {
    T parse(String[] fields);
    String[] serialize(T obj);
}
