package org.sec.Data;

import java.util.Objects;

/** 方法引用对象,用于表示一个类的各种信息 */
public class MethodReference {
    private final String owner;
    private final String name;
    private final String desc;
    private final boolean isStatic;

    public MethodReference(String owner, String name, String desc, boolean isStatic) {
        this.owner = owner;
        this.name = name;
        this.desc = desc;
        this.isStatic = isStatic;
    }

    public String getOwner() {
        return owner;
    }

    public String getName() {
        return name;
    }

    public String getDesc() {
        return desc;
    }

    public boolean isStatic() {
        return isStatic;
    }

    // 类似于windows api编程中的 handle
    public static class Handle {
        private final String owner;
        private final String name;
        private final String desc;

        public Handle(String owner, String name, String desc) {
            this.owner = owner;
            this.name = name;
            this.desc = desc;
        }

        public String getOwner() {
            return owner;
        }

        public String getName() {
            return name;
        }

        public String getDesc() {
            return desc;
        }

        @Override
        public String toString() {
            return "Handle{" +
                    "owner='" + owner + '\'' +
                    ", name='" + name + '\'' +
                    ", desc='" + desc + '\'' +
                    '}';
        }
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Handle handle = (Handle) o;

            if (!Objects.equals(owner, handle.owner))
                return false;
            if (!Objects.equals(name, handle.name)) return false;
            return Objects.equals(desc, handle.desc);
        }

        @Override
        public int hashCode() {
            int result = owner != null ? owner.hashCode() : 0;
            result = 31 * result + (name != null ? name.hashCode() : 0);
            result = 31 * result + (desc != null ? desc.hashCode() : 0);
            return result;
        }
    }

    /** 工厂类,用于返回 方法引用对象 和 方法引用对象的序列化数据 */
    public static class Factory implements DataFactory<MethodReference> {
        @Override
        public MethodReference parse(String[] fields) {
            return new MethodReference(
                    fields[0],
                    fields[1],
                    fields[2],
                    Boolean.parseBoolean(fields[3]));
        }

        @Override
        public String[] serialize(MethodReference obj) {
            return new String[] {
                    obj.getOwner(),
                    obj.name,
                    obj.desc,
                    Boolean.toString(obj.isStatic),
            };
        }
    }
}

