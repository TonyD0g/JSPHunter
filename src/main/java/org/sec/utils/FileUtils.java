package org.sec.utils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import org.apache.log4j.Logger;

/**
 * 文件操作
 */
public class FileUtils {
    private static final Logger logger = Logger.getLogger(FileUtils.class);
    private static final boolean DEBUG = true;

    /** 创建文件 */
    public static boolean creatFile(String filePath){
        File file = new File(filePath);
        try {
            file.createNewFile();
            return true;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * 获取文件路径
     */
    public static String getFilePath(String relativePath) {
        String dir = FileUtils.class.getResource("/").getPath();
        return dir + relativePath;
    }

    /**
     * 返回字节码文件路径
     */
    public static String getFilePath(Class<?> clazz, String className) {
        String path = clazz.getResource("/").getPath();
        return String.format("%s%s.class", path, className.replace('.', File.separatorChar));
    }

    /** 根据想要的后缀名读取文件到列表中  (读取)*/
    public static void getWantSuffixFilePath(String path, String wantSuffix,ArrayList<String> filePathArray) {
        ArrayList<String> filePathList = new ArrayList<>();
        readDir(path, filePathList);
        String suffix;
        for (String filePath : filePathList) {
            suffix = readSuffix(filePath);
            if(Objects.equals(suffix, wantSuffix)){
                filePathArray.add(filePath);
            }
        }
    }

    /**
     * 根据输入的filePath读取Bytes (读取)
     */
    public static byte[] readBytes(String filePath) {
        File file = new File(filePath);
        if (!file.exists()) {
            throw new IllegalArgumentException("[INFO] [org.sec.utils.FileUtils] File Not Exist: " + filePath);
        }

        InputStream in = null;

        try {
            in = Files.newInputStream(file.toPath());
            in = new BufferedInputStream(in);

            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            IOUtils.copy(in, bao);

            return bao.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            IOUtils.closeQuietly(in);
        }

        throw new RuntimeException("[Waring] [org.sec.utils.FileUtils] Can not read file: " + filePath);
    }

    /**
     * 读文件 (读取)
     */
    public static FileReader readForName(String name) throws Exception {
        FileReader fileName = null;
        try {
            fileName = new FileReader(String.format("src/main/java/Data/%s", name));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return fileName;
    }

    /**
     * 读文件 (读取)
     */
    public static List<String> readLines(String filepath) {
        return readLines(filepath, "UTF8");
    }

    /**
     * 从文件中按行全部读入List<String>中 (读取)
     */
    public static List<String> readLines(String filepath, String charsetName) {
        File file = new File(filepath);
        if (!file.exists()) {
            throw new IllegalArgumentException("[Waring] [org.sec.utils.FileUtils] File Not Exist: " + filepath);
        }

        InputStream in = null;
        Reader reader = null;
        BufferedReader bufferReader = null;

        try {
            in = Files.newInputStream(file.toPath());
            reader = new InputStreamReader(in, charsetName);
            bufferReader = new BufferedReader(reader);

            List<String> list = new ArrayList<>();
            String line;
            while ((line = bufferReader.readLine()) != null) {
                list.add(line);
            }
            return list;
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            IOUtils.closeQuietly(bufferReader);
            IOUtils.closeQuietly(reader);
            IOUtils.closeQuietly(in);
        }

        assert !DEBUG : "[Waring] [org.sec.utils.FileUtils] bytes is null";

        return null;
    }


    /**
     * 随机读取某一行 (读取)
     */
    public static String randomReadLine(int maxLine, FileReader fileName) throws Exception {
        int wantLine = (int) (Math.random() * maxLine + 1), line = 1;
        BufferedReader in = new BufferedReader(fileName);
        String str;
        while ((str = in.readLine()) != null) {
            if (wantLine == line) {
                return str;
            }
            line++;
        }

        return null;
    }

    /**
     * 读文件流 (读取)
     */
    public static byte[] readStream(final InputStream in, final boolean close) {
        if (in == null) {
            throw new IllegalArgumentException("[Waring] [org.sec.utils.FileUtils] inputStream is null!!!");
        }

        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            IOUtils.copy(in, out);
            return out.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (close) {
                IOUtils.closeQuietly(in);
            }
        }
        return null;
    }

    public static String readSuffix(String fileName) {
        return fileName.split("\\.")[fileName.split("\\.").length - 1];
    }

    /**
     * 写入Bytes (写入)
     */
    public static void writeBytes(String filepath, byte[] bytes) {
        File file = new File(filepath);
        File dirFile = file.getParentFile();
        mkdir(dirFile);

        try (OutputStream out = new FileOutputStream(filepath);
             BufferedOutputStream buff = new BufferedOutputStream(out)) {
            buff.write(bytes);
            buff.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (DEBUG) logger.info("file://" + filepath);
    }

    /**
     * 将多行写到文件 (写入)
     */
    public static void writeLines(String filepath, List<String> lines) {
        if (lines == null || lines.size() < 1) return;

        File file = new File(filepath);
        File dirFile = file.getParentFile();
        mkdir(dirFile);

        OutputStream out = null;
        Writer writer = null;
        BufferedWriter bufferedWriter = null;

        try {
            out = new FileOutputStream(file);
            writer = new OutputStreamWriter(out, StandardCharsets.UTF_8);
            bufferedWriter = new BufferedWriter(writer);

            for (String line : lines) {
                bufferedWriter.write(line);
                bufferedWriter.newLine();
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        } finally {
            IOUtils.closeQuietly(bufferedWriter);
            IOUtils.closeQuietly(writer);
            IOUtils.closeQuietly(out);
        }
    }


    /**
     * 输入str,尝试获取其在文件中的行数
     */
    public static int useStrToGetLineNum(BufferedReader reader, String wantStr) throws Exception {

        String str;
        int lineNum = 0;
        while ((str = reader.readLine()) != null) {
            lineNum++;
            if (str.equals(wantStr)) {
                String outcome = String.format("[+] has found that the \"%s\" in the file's lineNum: %d", str, lineNum);
                logger.info(outcome);
                break;
            }
        }
        return lineNum;
    }

    /**
     * 刷新目录
     */
    public static void flushDir(String wantFlushDir) {
        File file = new File(wantFlushDir);
        if (file.exists()) {
            delete(file);
        }
        file.mkdir();
    }

    /**
     * 创建目录
     */
    public static void mkdir(File dirFile) {
        boolean file_exists = dirFile.exists();

        if (file_exists && dirFile.isDirectory()) {
            return;
        }

        if (file_exists && dirFile.isFile()) {
            throw new RuntimeException("[Waring] [org.sec.utils.FileUtils] Not A Directory: " + dirFile);
        }

        if (!file_exists) {
            boolean flag = dirFile.mkdirs();
            assert !DEBUG || flag : "[-] [org.sec.utils.FileUtils] Create Directory Failed: " + dirFile.getAbsolutePath();
        }
    }

    /**
     * 读取dir下的所有文件,返回绝对路径列表 (读取)
     */
    public static ArrayList<String> readDir(String pathName, ArrayList<String> fileNameList) {
        File folder = new File(pathName);
        if (!folder.isDirectory()) {
            fileNameList.add(folder.getAbsolutePath());
            return null;
        }
        File[] files = folder.listFiles();
        assert files != null;
        for (File a : files) {
            if (a.isDirectory()) {
                readDir(a.getAbsolutePath(), fileNameList);
            } else {
                fileNameList.add(a.getAbsolutePath());
            }
        }

        return fileNameList;
    }

    /**
     * 读取 WebDir (读取)
     */
    public static Set<String> readWebDir(String webDir, Set<String> webDirSet) {
        ArrayList<String> allFileName = new ArrayList<>();
        readDir(webDir, allFileName);
        for (String filename : allFileName) {
            String tag = File.separator + "WEB-INF" + File.separator;
            int point = filename.indexOf(tag);
            if (point > -1) {
                webDirSet.add(filename.substring(0, point));
            }
        }
        return webDirSet;
    }

    /**
     * 删除文件
     */
    public static void clear(File file) {
        if (!file.exists()) {
            return;
        }

        if (file.isDirectory()) {
            File[] files = file.listFiles();
            if (files != null && files.length > 0) {
                for (File f : files) {
                    delete(f);
                }
            }
        } else {
            delete(file);
        }
    }

    /**
     * 删除文件
     */
    public static void delete(File file) {
        if (!file.exists()) {
            return;
        }

        if (file.isFile()) {
            boolean flag = file.delete();
            assert !DEBUG || flag : "[Warning] [org.sec.utils.FileUtils] delete file failed: " + file.getAbsolutePath();
        }

        if (file.isDirectory()) {
            File[] files = file.listFiles();
            if (files != null) {
                for (File f : files) {
                    delete(f);
                }
            }

            boolean flag = file.delete();
            assert !DEBUG || flag : "[Warning] [org.sec.utils.FileUtils] delete file failed: " + file.getAbsolutePath();
        }
    }


    /**
     * 获取输入流
     */
    public static InputStream getInputStream(String className) {
        return ClassLoader.getSystemResourceAsStream(className.replace('.', '/') + ".class");
    }

}

