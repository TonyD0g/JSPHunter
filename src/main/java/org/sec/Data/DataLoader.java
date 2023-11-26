package org.sec.Data;

import com.google.common.io.Files;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.*;

public class DataLoader {
    public static <T> List<T> loadData(String filePath, DataFactory<T> factory) throws IOException, ClassNotFoundException {
        InputStream is = Class.forName("org.sec.Main").getResourceAsStream(filePath);
        assert is != null;
        BufferedReader br = new BufferedReader(new InputStreamReader(is));
        String s;
        final List<T> values = new ArrayList<>();
        while ((s = br.readLine()) != null) {
            values.add(factory.parse(s.split("\t", -1)));
        }
        return values;
    }

    public static <T> void saveData(Path filePath, DataFactory<T> factory, Collection<T> values) throws IOException {
        try (BufferedWriter writer = Files.newWriter(filePath.toFile(), StandardCharsets.UTF_8)) {
            for (T value : values) {
                final String[] fields = factory.serialize(value);
                if (fields == null) {
                    continue;
                }

                StringBuilder sb = new StringBuilder();
                for (String field : fields) {
                    if (field == null) {
                        sb.append("\t");
                    } else {
                        sb.append("\t").append(field);
                    }
                }
                writer.write(sb.substring(1));
                writer.write("\n");
            }
        }
    }
}

