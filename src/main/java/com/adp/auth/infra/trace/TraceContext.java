package com.adp.auth.infra.trace;

import org.slf4j.MDC;

import java.security.SecureRandom;

/** 链路追踪上下文 —— traceId 写入 MDC，日志统一带 [traceId=...]；跨服务由 X-Request-Id 头透传。 */
public final class TraceContext {

    public static final String MDC_KEY = "traceId";

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private TraceContext() {}

    /** 当前 traceId（无则生成）。 */
    public static String current() {
        String cur = MDC.get(MDC_KEY);
        if (cur == null || cur.isBlank()) {
            cur = newTraceId();
            MDC.put(MDC_KEY, cur);
        }
        return cur;
    }

    /** 接收上游透传的 traceId（校验 hex 格式，非法则忽略）。 */
    public static void setIfPresent(String traceId) {
        if (traceId != null && traceId.matches("[0-9a-fA-F]{1,32}")) {
            MDC.put(MDC_KEY, traceId.toLowerCase());
        }
    }

    /** 恢复上一 traceId（绝不裸 MDC.clear()，避免污染线程池复用线程）。 */
    public static void restorePrev(String prev) {
        if (prev == null) {
            MDC.remove(MDC_KEY);
        } else {
            MDC.put(MDC_KEY, prev);
        }
    }

    private static String newTraceId() {
        byte[] bytes = new byte[6];
        RANDOM.nextBytes(bytes);
        char[] out = new char[12];
        for (int i = 0; i < bytes.length; i++) {
            out[i * 2] = HEX[(bytes[i] >> 4) & 0xF];
            out[i * 2 + 1] = HEX[bytes[i] & 0xF];
        }
        return new String(out);
    }
}
