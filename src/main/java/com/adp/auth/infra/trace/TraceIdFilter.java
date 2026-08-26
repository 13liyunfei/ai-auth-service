package com.adp.auth.infra.trace;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * 链路追踪 Filter —— 与 ai-data-platform 的 TraceIdFilter 同构：
 * 接收上游透传的 X-Request-Id / X-Trace-Id（platform → auth 调用链同源 traceId），
 * 无则生成 12 位 hex，写 MDC（日志带 [traceId=...]），响应头回传。
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class TraceIdFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-Request-Id";
    private static final String ALT_HEADER = "X-Trace-Id";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String incoming = request.getHeader(HEADER);
        if (incoming == null) incoming = request.getHeader(ALT_HEADER);
        String prev = org.slf4j.MDC.get(TraceContext.MDC_KEY);
        TraceContext.setIfPresent(incoming);
        try {
            response.setHeader(HEADER, TraceContext.current());
            chain.doFilter(request, response);
        } finally {
            TraceContext.restorePrev(prev);
        }
    }
}
