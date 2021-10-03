package org.javaboy.vhr.config;

import org.javaboy.vhr.model.Menu;
import org.javaboy.vhr.model.Role;
import org.javaboy.vhr.service.MenuService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Collection;
import java.util.List;

/**自定义权限拦截
 * 这个类的作用，主要是根据用户传来的请求地址，分析出请求需要的角色
 * 用于配置SecurityConfig.java，属于一个配置策略的类
 * 每次请求都会经过这个类
 */
@Component
public class CustomFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {
    @Autowired
    MenuService menuService;
    //用于匹配路径，ant风格路径匹配符
    AntPathMatcher antPathMatcher = new AntPathMatcher();
    @Override
    //根据请求的Url返回所需角色
    //核心方法：getAttributes(Object object);其中object是一个类似Http Request的对象
    //从object中获取客户端请求的Url，之后从数据库中查询出所有的菜单Url以及哪些角色可以访问对应的菜单Url
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        String requestUrl = ((FilterInvocation) object).getRequestUrl();
        //获取所有的菜单
        List<Menu> menus = menuService.getAllMenusWithRole();
        for (Menu menu : menus) {
            //如果匹配得到，就获取该路径的角色
            if (antPathMatcher.match(menu.getUrl(), requestUrl)) {
                List<Role> roles = menu.getRoles();
                String[] str = new String[roles.size()];
                for (int i = 0; i < roles.size(); i++) {
                    str[i] = roles.get(i).getName();
                }
                //之后包装成SecurityConfig中的一个属性
                return SecurityConfig.createList(str);
            }
        }
        //一些匹配不到的路径，由于目前的项目只有登录页面不需要登录就能访问，
        //而其他Url都是需要登录后才能拿到  因此要创建一个“ROLE_LOGIN”角色来
        //保证Url的权限。
        return SecurityConfig.createList("ROLE_LOGIN");
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }
}
