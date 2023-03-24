package org.sec.http;

import org.apache.http.client.CookieStore;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;

import java.util.Map;

public class CookieStoreParams {
    public CookieStore cookieStore;
    public Map<String, String> HttpBodyParams;
    public HttpPost post;
    public CloseableHttpClient httpClient;
    public CloseableHttpResponse response;
}
