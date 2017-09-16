package com.har.unmanned.mfront.utils;

import com.alibaba.fastjson.JSONObject;
import com.google.common.collect.Maps;

import com.har.unmanned.mfront.config.Constants;
import com.har.unmanned.mfront.config.ErrorCode;
import com.har.unmanned.mfront.exception.ApiBizException;
import com.har.unmanned.mfront.model.ShopWechat;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.joda.time.DateTime;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.text.MessageFormat;
import java.util.Date;
import java.util.Map;

/**
 * JWT校验
 */
@Slf4j
@Component
public class JwtUtil {
    @Value("${client.client-secret}")
    String key;

    public String  getAccessToken(ShopWechat wxUser) throws ApiBizException {
        String jwt="";
        // 返回消息
        RespMessage respMessage = new RespMessage();

        try {
            String openid = wxUser.getOpenid();
                // 用户相关权限校验
                Map<String, Object> claims = Maps.newHashMap();
                claims.put("openId", openid);
                claims.put("exp", 1200);
                // TODO 将data转换成jwt
                jwt = create(claims);
                log.debug("{}, {}", claims, jwt);
        } catch (Exception e) {
            e.printStackTrace();
            log.error("=====获取授权码错误=====", e);
            throw new ApiBizException(ErrorCode.E00000007.CODE, ErrorCode.E00000007.MSG, e);
        }
        return jwt;
    }

    public String create(Map<String, Object> claims) {
        Map<String, Object> header = Maps.newHashMap();
        header.put("typ", "JWT");
        return Jwts.builder()
                .setHeader(header)
                .setClaims(claims)
                .setExpiration((Date) claims.get("exp"))
                .signWith(SignatureAlgorithm.HS256, key.getBytes())
                .compact();
    }

}
