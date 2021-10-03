package org.javaboy.vhr.config;

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collection;

/**
 *
 */
@Component
//分析当前用户是否具有需要的角色
public class CustomUrlDecisionManager implements AccessDecisionManager {
    @Override
    //用于决定允不允许客户端访问这个这个url
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) throws
            AccessDeniedException, InsufficientAuthenticationException {
        for (ConfigAttribute configAttribute : configAttributes) {
            String needRole = configAttribute.getAttribute();
            //这里对应的是没有匹配到角色的Url，默认是需要登录后才能访问
            //如果没登录（authentication instanceof AnonymousAuthenticationToken）则抛出异常
            if ("ROLE_LOGIN".equals(needRole)) {
                if (authentication instanceof AnonymousAuthenticationToken) {
                    throw new AccessDeniedException("尚未登录，请登录!");
                }else {
                    return;
                }
            }
            //如果用户自带的角色中有一个符合所需对象集合中的一个，那么就能访问请求的Url，如果不能则抛出异常
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();//获取登陆用户中的所有权限
            for (GrantedAuthority authority : authorities) {
                if (authority.getAuthority().equals(needRole)) {
                    return;
                }
            }
        }
        throw new AccessDeniedException("权限不足，请联系管理员!");
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }
}
