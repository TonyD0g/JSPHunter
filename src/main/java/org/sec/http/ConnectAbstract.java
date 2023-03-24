package org.sec.http;

import org.apache.http.NameValuePair;
import org.apache.http.client.CookieStore;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.message.BasicNameValuePair;
import org.apache.log4j.Logger;

import java.io.UnsupportedEncodingException;
import java.util.*;

/** 用于提供http连接服务*/
public abstract class ConnectAbstract {
    public static CookieStoreParams cookieStoreParams = new CookieStoreParams();
    private static final Logger logger = Logger.getLogger(ConnectAbstract.class);

    /**
     * 创建一个新的UUID
     */
    public static String createUUID() {
        UUID uuid4 = UUID.randomUUID();
        String uuid = String.valueOf(uuid4);
        logger.info("[+] originUUID: " + uuid);

        // uuid 格式： 8-4-4-4-12
        return uuid;
    }

    /** 设置cookie值*/
    public static CookieStore setCookie(CookieStore cookieStore,BasicClientCookie cookie,String setPath,String setDomain) throws Exception {
        // cookie为变量
        cookie.setPath(setPath);
        cookie.setDomain(setDomain);
        cookieStore.addCookie(cookie);
        logger.info(cookie);

        return cookieStore;
    }

    /** 添加文本(加密/不加密)到http请求正文中 */
    public static void addTextToBody(Map<String, String> HttpBodyParams, StringBuilder text, HttpPost post) throws UnsupportedEncodingException {
        // 添加文本(加密/不加密的)到http请求正文中
        HttpBodyParams.put("sentence", String.valueOf(text));

        //4.添加参数
        List<NameValuePair> parameters = new ArrayList<>();
        for (Map.Entry<String, String> entry : HttpBodyParams.entrySet()) {
            parameters.add(new BasicNameValuePair(entry.getKey(), entry.getValue()));
        }

        UrlEncodedFormEntity formEntity = new UrlEncodedFormEntity(parameters, "UTF-8");
        post.setEntity(formEntity);
    }

    /**
     * 连接Shell ,返回一个 http 对象
     */
    public static void connectShell(String url) throws Exception {
        CookieStore cookieStore = new BasicCookieStore();
        //创建httpClient实例
        CloseableHttpClient httpClient = HttpClients.custom().setDefaultCookieStore(cookieStore).build();
        RequestConfig requestConfig = RequestConfig.custom().setConnectTimeout(4000).setSocketTimeout(8000).build();
        
        //创建一个uri对象
        URIBuilder uriBuilder = new URIBuilder(url);
        //创建httpPost远程连接实例,这里传入目标的网络地址
        HttpPost post = new HttpPost(uriBuilder.build());
        post.setConfig(requestConfig);

        Map<String, String> HttpBodyParams = new HashMap<>();

        cookieStoreParams.cookieStore = cookieStore;
        cookieStoreParams.HttpBodyParams = HttpBodyParams;
        cookieStoreParams.post = post;
        cookieStoreParams.httpClient = httpClient;
    }

}

