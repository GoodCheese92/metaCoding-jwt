package com.example.jwt.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;

        // 토큰 :  cos 이걸 만들어줘야 함. id, pw 정상적으로 들어와서 로그인이 왼료 되면 토큰을 만들어주고 그걸 응답을 해준다.
        // 요청할 때 마다 header에 Authorization에 value값으로 토큰을 가지고 온다.
        // 그 때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증만 하면 됨. (RSA, HS256)
        if(httpServletRequest.getMethod().equals("POST")){
            System.out.println("POST 요청됨");
            String headerAuth = httpServletRequest.getHeader("Authorization");
            System.out.println(headerAuth);
            System.out.println("필터3");

            if(headerAuth.equals("cos")){
                chain.doFilter(httpServletRequest, httpServletResponse);
            } else {
                PrintWriter outPrintWriter = httpServletResponse.getWriter();
                outPrintWriter.println("인증 안됨");
            }
        }
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);
    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }
} // end of class
